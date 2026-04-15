from __future__ import annotations

import contextlib
import time
from typing import Any

import requests

from domain_audit.grader import ScanResult, worst_grade
from domain_audit.rate_limit import throttle
from domain_audit.retry import RetryConfig, with_retry
from domain_audit.validators import safe_error

SECURITY_HEADERS = {
    "X-Content-Type-Options": {
        "label": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "fix": "Add header: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "label": "X-Frame-Options",
        "severity": "MEDIUM",
        "fix": "Add header: X-Frame-Options: DENY (or SAMEORIGIN)",
    },
    "Referrer-Policy": {
        "label": "Referrer-Policy",
        "severity": "LOW",
        "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "label": "Permissions-Policy",
        "severity": "LOW",
        "fix": "Add a Permissions-Policy header to control browser feature access",
    },
}

# Minimum max-age (in seconds) considered strong: 1 year
_HSTS_STRONG_MAX_AGE = 31536000
# 6 months — acceptable but not ideal
_HSTS_ACCEPTABLE_MAX_AGE = 15768000


def _grade_hsts(headers_lower: dict[str, str]) -> dict[str, Any]:
    """Grade HSTS header quality, not just presence."""
    value = headers_lower.get("strict-transport-security")
    if not value:
        return {
            "label": "HSTS (Strict-Transport-Security)",
            "value": "Not set",
            "grade": "F",
            "detail": "HSTS header is missing — browsers won't enforce HTTPS",
            "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        }

    directives = [d.strip().lower() for d in value.split(";")]
    max_age = 0
    for d in directives:
        if d.startswith("max-age"):
            with contextlib.suppress(IndexError, ValueError):
                max_age = int(d.split("=", 1)[1].strip())

    has_subdomains = any(d == "includesubdomains" for d in directives)
    has_preload = any(d == "preload" for d in directives)

    if max_age <= 0:
        return {
            "label": "HSTS (Strict-Transport-Security)",
            "value": value,
            "grade": "F",
            "detail": "HSTS max-age is 0 or invalid — effectively disabled",
            "fix": "Set max-age to at least 31536000 (1 year)",
        }

    if max_age >= _HSTS_STRONG_MAX_AGE and has_subdomains:
        detail = f"HSTS max-age={max_age}, includeSubDomains"
        if has_preload:
            detail += ", preload"
        return {
            "label": "HSTS (Strict-Transport-Security)",
            "value": value,
            "grade": "A",
            "detail": detail,
            "fix": "",
        }

    if max_age >= _HSTS_STRONG_MAX_AGE:
        return {
            "label": "HSTS (Strict-Transport-Security)",
            "value": value,
            "grade": "B",
            "detail": f"HSTS max-age={max_age} but missing includeSubDomains",
            "fix": "Add includeSubDomains to protect all subdomains",
        }

    fix_parts = [f"Increase max-age to {_HSTS_STRONG_MAX_AGE}"]
    if not has_subdomains:
        fix_parts.append("add includeSubDomains")

    return {
        "label": "HSTS (Strict-Transport-Security)",
        "value": value,
        "grade": "C" if max_age < _HSTS_ACCEPTABLE_MAX_AGE else "B",
        "detail": f"HSTS max-age={max_age} is below recommended 1-year minimum",
        "fix": "; ".join(fix_parts),
    }


def _grade_csp(headers_lower: dict[str, str]) -> dict[str, Any]:
    """Grade CSP quality: enforcing > report-only > absent."""
    enforcing = headers_lower.get("content-security-policy")
    report_only = headers_lower.get("content-security-policy-report-only")

    if enforcing:
        policy_lower = enforcing.lower()
        has_unsafe_inline = "'unsafe-inline'" in policy_lower
        has_unsafe_eval = "'unsafe-eval'" in policy_lower
        has_wildcard = "default-src *" in policy_lower or "default-src: *" in policy_lower

        if has_wildcard:
            return {
                "label": "Content-Security-Policy",
                "value": enforcing,
                "grade": "C",
                "detail": "CSP uses wildcard default-src — provides no meaningful protection",
                "fix": "Replace default-src * with a restrictive policy",
            }

        issues = []
        if has_unsafe_inline:
            issues.append("unsafe-inline")
        if has_unsafe_eval:
            issues.append("unsafe-eval")

        if issues:
            return {
                "label": "Content-Security-Policy",
                "value": enforcing,
                "grade": "B",
                "detail": f"CSP is enforcing but uses {', '.join(issues)}",
                "fix": f"Remove {', '.join(issues)} from CSP — use nonces or hashes instead",
            }

        return {
            "label": "Content-Security-Policy",
            "value": enforcing,
            "grade": "A",
            "detail": "CSP is enforcing with no unsafe directives",
            "fix": "",
        }

    if report_only:
        return {
            "label": "Content-Security-Policy",
            "value": f"(Report-Only) {report_only}",
            "grade": "B",
            "detail": "CSP is in report-only mode — violations logged but not blocked",
            "fix": "Promote Content-Security-Policy-Report-Only to enforcing Content-Security-Policy",
        }

    return {
        "label": "Content-Security-Policy",
        "value": "Not set",
        "grade": "C",
        "detail": "No Content-Security-Policy header — vulnerable to XSS and injection",
        "fix": "Add a Content-Security-Policy header to prevent XSS and data injection",
    }


_retry = RetryConfig(max_retries=2, timeout_per_attempt=10.0)


@with_retry(config=_retry)
def _fetch_headers(domain: str) -> dict[str, str]:
    throttle(f"https://{domain}")
    resp = requests.get(
        f"https://{domain}",
        timeout=_retry.timeout_per_attempt,
        allow_redirects=True,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    return dict(resp.headers)


def _check_redirect_chain(domain: str) -> dict[str, Any]:
    """Follow redirects step by step and analyze the chain."""
    chain: list[dict[str, str]] = []
    issues: list[str] = []

    try:
        throttle(f"http://{domain}")
        resp = requests.get(
            f"http://{domain}",
            timeout=10.0,
            allow_redirects=False,
            headers={"User-Agent": "domain-audit/0.1"},
        )

        chain.append(
            {
                "url": f"http://{domain}",
                "status": str(resp.status_code),
                "location": resp.headers.get("Location", "-"),
            }
        )

        # Follow up to 10 redirects
        current_url = resp.headers.get("Location", "")
        seen = {f"http://{domain}"}
        hops = 0

        while current_url and hops < 10:
            if current_url in seen:
                issues.append(f"Redirect loop detected at {current_url}")
                break
            seen.add(current_url)
            hops += 1

            try:
                throttle(current_url)
                resp = requests.get(
                    current_url,
                    timeout=10.0,
                    allow_redirects=False,
                    headers={"User-Agent": "domain-audit/0.1"},
                )
                location = resp.headers.get("Location", "")
                chain.append(
                    {
                        "url": current_url,
                        "status": str(resp.status_code),
                        "location": location or "(final)",
                    }
                )

                # Check for HTTP > HTTPS > HTTP downgrade
                if current_url.startswith("https://") and location.startswith("http://"):
                    issues.append(f"HTTPS downgrade: redirects from HTTPS back to HTTP at {location}")

                if resp.status_code in (301, 302, 303, 307, 308):
                    current_url = location
                else:
                    break

            except Exception as e:
                chain.append(
                    {
                        "url": current_url,
                        "status": f"Error: {e}",
                        "location": "-",
                    }
                )
                break

        # Check chain length
        if len(chain) > 3:
            issues.append(f"Long redirect chain ({len(chain)} hops) — impacts page load time")

        # Check HTTP to HTTPS redirect
        first_http = chain[0]["url"].startswith("http://") if chain else False
        has_https_redirect = any(
            c["location"].startswith("https://") for c in chain if c.get("location", "").startswith("https://")
        )
        if first_http and not has_https_redirect and len(chain) > 1:
            issues.append("HTTP does not redirect to HTTPS")

    except Exception as e:
        issues.append(f"Could not check redirects: {e}")

    return {
        "chain": chain,
        "hops": len(chain),
        "issues": issues,
    }


def _check_cookies(domain: str) -> dict[str, Any]:
    """Check Set-Cookie headers for security flags."""
    cookies: list[dict[str, Any]] = []
    issues: list[str] = []

    try:
        throttle(f"https://{domain}")
        resp = requests.get(
            f"https://{domain}",
            timeout=10.0,
            allow_redirects=True,
            headers={"User-Agent": "domain-audit/0.1"},
        )

        set_cookie_headers = []
        # requests stores all Set-Cookie in response.headers as a single joined string
        # Use raw headers from urllib3 for multiple Set-Cookie
        if hasattr(resp.raw, "_original_response") and resp.raw._original_response:
            raw_headers = resp.raw._original_response.headers.get_all("Set-Cookie") or []
            set_cookie_headers = [h for h in raw_headers if h]

        if not set_cookie_headers:
            # Fallback
            sc = resp.headers.get("Set-Cookie", "")
            if sc:
                set_cookie_headers = [sc]

        for cookie_str in set_cookie_headers:
            name = cookie_str.split("=", 1)[0].strip() if "=" in cookie_str else cookie_str.split(";")[0].strip()

            # Parse cookie attributes by splitting on semicolons
            # Attributes are after the first name=value pair
            attrs = [a.strip().lower() for a in cookie_str.split(";")[1:]]
            attr_names = [a.split("=")[0].strip() for a in attrs]

            has_secure = "secure" in attr_names
            has_httponly = "httponly" in attr_names
            has_samesite = any(a.startswith("samesite") for a in attr_names)

            cookie_issues = []
            if not has_secure:
                cookie_issues.append("Missing Secure flag")
            if not has_httponly:
                cookie_issues.append("Missing HttpOnly flag")
            if not has_samesite:
                cookie_issues.append("Missing SameSite flag")

            cookies.append(
                {
                    "name": name[:40],
                    "secure": has_secure,
                    "httponly": has_httponly,
                    "samesite": has_samesite,
                    "issues": cookie_issues,
                }
            )

            if cookie_issues:
                issues.extend(f"Cookie '{name}': {i}" for i in cookie_issues)

    except Exception:
        pass

    return {
        "cookies": cookies,
        "issues": issues,
    }


def scan(domain: str) -> ScanResult:
    start = time.time()
    retries = 0
    findings = []
    raw_data: dict[str, Any] = {}

    try:
        response_headers = _fetch_headers(domain)
        raw_data["headers"] = response_headers

        # Build lowercase lookup once
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        # ── HSTS (quality-graded) ──
        hsts_finding = _grade_hsts(headers_lower)
        findings.append(hsts_finding)

        # ── CSP (quality-graded) ──
        csp_finding = _grade_csp(headers_lower)
        findings.append(csp_finding)

        # ── Other security headers (presence check) ──
        for header_name, meta in SECURITY_HEADERS.items():
            found = header_name.lower() in headers_lower
            header_value = headers_lower.get(header_name.lower())

            if found:
                grade = "A"
                detail = f"{meta['label']} is set"
            else:
                grade = "B"
                detail = f"{meta['label']} is missing"

            findings.append(
                {
                    "label": meta["label"],
                    "value": header_value or "Not set",
                    "grade": grade,
                    "detail": detail,
                    "fix": "" if found else meta["fix"],
                }
            )

        # ── Redirect chain analysis ──
        redirect = _check_redirect_chain(domain)
        raw_data["redirect_chain"] = redirect

        if redirect["issues"]:
            has_downgrade = any("downgrade" in i.lower() for i in redirect["issues"])
            redirect_grade = "F" if has_downgrade else "C"
            redirect_detail = "; ".join(redirect["issues"])
        else:
            redirect_grade = "A"
            redirect_detail = f"Clean redirect chain ({redirect['hops']} hop(s), HTTP→HTTPS)"

        redirect_tests = []
        redirect_tests.append(
            {
                "test": "Redirect Chain Length",
                "pass": redirect["hops"] <= 3,
                "result": f"{redirect['hops']} hop(s)"
                + (" — too many redirects" if redirect["hops"] > 3 else " — acceptable"),
            }
        )

        has_http_to_https = any(
            c["url"].startswith("http://") and c.get("location", "").startswith("https://") for c in redirect["chain"]
        )
        redirect_tests.append(
            {
                "test": "HTTP to HTTPS Redirect",
                "pass": has_http_to_https,
                "result": "HTTP redirects to HTTPS" if has_http_to_https else "No HTTP→HTTPS redirect found",
            }
        )

        has_loop = any("loop" in i.lower() for i in redirect["issues"])
        redirect_tests.append(
            {
                "test": "Redirect Loop",
                "pass": not has_loop,
                "result": "No redirect loop detected" if not has_loop else "Redirect loop detected",
            }
        )

        has_downgrade = any("downgrade" in i.lower() for i in redirect["issues"])
        redirect_tests.append(
            {
                "test": "HTTPS Downgrade",
                "pass": not has_downgrade,
                "result": "No HTTPS downgrade" if not has_downgrade else "HTTPS redirects back to HTTP",
            }
        )

        # Build chain as parsed table
        chain_parsed = [
            {"tag": str(i + 1), "value": c["url"], "name": c["status"], "description": f"→ {c['location']}"}
            for i, c in enumerate(redirect["chain"])
        ]

        findings.append(
            {
                "label": "Redirect Chain",
                "value": redirect["chain"],
                "grade": redirect_grade,
                "detail": redirect_detail,
                "fix": "Fix redirect chain issues" if redirect["issues"] else "",
                "parsed_record": chain_parsed,
                "tests": redirect_tests,
                "record_type": "Redirect Chain",
                "domain": domain,
            }
        )

        # ── Cookie security ──
        cookie_check = _check_cookies(domain)
        raw_data["cookies"] = cookie_check
        cookie_grade = "-"

        if cookie_check["cookies"]:
            insecure_count = sum(1 for c in cookie_check["cookies"] if c["issues"])
            if insecure_count == 0:
                cookie_grade = "A"
                cookie_detail = (
                    f"All {len(cookie_check['cookies'])} cookie(s) have Secure, HttpOnly, and SameSite flags"
                )
            else:
                cookie_grade = "C"
                cookie_detail = f"{insecure_count} of {len(cookie_check['cookies'])} cookie(s) missing security flags"

            cookie_tests = []
            for c in cookie_check["cookies"]:
                cookie_tests.append(
                    {
                        "test": f"Cookie '{c['name']}' Secure",
                        "pass": c["secure"],
                        "result": "Secure flag set" if c["secure"] else "Missing Secure flag — cookie sent over HTTP",
                    }
                )
                cookie_tests.append(
                    {
                        "test": f"Cookie '{c['name']}' HttpOnly",
                        "pass": c["httponly"],
                        "result": "HttpOnly flag set"
                        if c["httponly"]
                        else "Missing HttpOnly — accessible via JavaScript",
                    }
                )
                cookie_tests.append(
                    {
                        "test": f"Cookie '{c['name']}' SameSite",
                        "pass": c["samesite"],
                        "result": "SameSite flag set" if c["samesite"] else "Missing SameSite — vulnerable to CSRF",
                    }
                )

            findings.append(
                {
                    "label": "Cookie Security",
                    "value": cookie_check["cookies"],
                    "grade": cookie_grade,
                    "detail": cookie_detail,
                    "fix": "Add Secure, HttpOnly, and SameSite flags to all cookies" if insecure_count > 0 else "",
                    "tests": cookie_tests,
                    "record_type": "Cookie Security",
                    "domain": domain,
                }
            )
        else:
            findings.append(
                {
                    "label": "Cookie Security",
                    "value": "No cookies set",
                    "grade": "-",
                    "detail": "No cookies set by the server",
                    "fix": "",
                }
            )

        # ── Calculate module grade from all finding grades ──
        all_grades = [str(f["grade"]) for f in findings if f["grade"] not in ("?", "-")]
        module_grade = worst_grade(all_grades) if all_grades else "?"

        status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

        return ScanResult(
            module="headers",
            status=status,
            grade=module_grade,
            findings=findings,
            raw_data=raw_data,
            elapsed=time.time() - start,
            retries=retries,
        )

    except Exception as exc:
        return ScanResult(
            module="headers",
            status="error",
            grade="?",
            findings=[
                {
                    "label": "HTTP Security Headers",
                    "value": f"Error: {safe_error(exc)}",
                    "grade": "?",
                    "detail": f"Could not fetch headers: {safe_error(exc)}",
                    "fix": "Verify the domain responds to HTTPS requests",
                }
            ],
            raw_data={"error": safe_error(exc)},
            elapsed=time.time() - start,
            retries=retries,
        )
