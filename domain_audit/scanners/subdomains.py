from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import dns.resolver
import dns.exception
import requests

from domain_audit.grader import ScanResult
from domain_audit.retry import RetryConfig, with_retry

_retry_ct = RetryConfig(max_retries=3, base_delay=2.0, timeout_per_attempt=15.0)
_retry_dns = RetryConfig(max_retries=2, timeout_per_attempt=5.0)

# Max subdomains to scan in detail (avoid hammering hundreds)
MAX_SUBDOMAIN_SCAN = 25


@with_retry(config=_retry_ct)
def _query_crtsh(domain: str) -> list[dict[str, Any]]:
    resp = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=_retry_ct.timeout_per_attempt,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    resp.raise_for_status()
    return resp.json()


def _discover_subdomains(domain: str) -> list[str]:
    """Discover subdomains via Certificate Transparency logs."""
    entries = _query_crtsh(domain)
    subdomains: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*"):
                if name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name)
    return sorted(subdomains)


# ═══════════════════════════════════════════════════════════════════
#  Per-subdomain probes
# ═══════════════════════════════════════════════════════════════════

def _probe_subdomain(sub: str) -> dict[str, Any]:
    """Run lightweight probes against a single subdomain."""
    result: dict[str, Any] = {
        "subdomain": sub,
        "dns": _probe_dns(sub),
        "ssl": _probe_ssl(sub),
        "http": _probe_http(sub),
    }
    return result


_retry_probe = RetryConfig(max_retries=1, base_delay=0.5, timeout_per_attempt=5.0)


def _probe_dns(sub: str) -> dict[str, Any]:
    """Resolve A/AAAA/CNAME for a subdomain with retry."""
    data: dict[str, Any] = {"a": [], "aaaa": [], "cname": []}
    for rdtype in ("A", "AAAA", "CNAME"):
        for attempt in range(2):  # 1 retry
            try:
                answers = dns.resolver.resolve(sub, rdtype, lifetime=5.0)
                data[rdtype.lower()] = [str(rdata) for rdata in answers]
                break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                break  # No point retrying these
            except Exception:
                if attempt == 0:
                    continue  # Retry on transient errors
    return data


def _probe_ssl(sub: str) -> dict[str, Any]:
    """Check SSL cert on port 443."""
    data: dict[str, Any] = {
        "has_ssl": False,
        "issuer": None,
        "expires": None,
        "days_left": None,
        "protocol": None,
        "valid": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=sub) as sock:
            sock.settimeout(5.0)
            sock.connect((sub, 443))
            cert = sock.getpeercert()
            protocol = sock.version()

        not_after = cert.get("notAfter", "")
        expiry_ts = ssl.cert_time_to_seconds(not_after)
        expiry_dt = datetime.fromtimestamp(expiry_ts, tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        days_left = (expiry_dt - now).days

        issuer = dict(x[0] for x in cert.get("issuer", []))

        data["has_ssl"] = True
        data["issuer"] = issuer.get("organizationName", "Unknown")
        data["expires"] = not_after
        data["days_left"] = days_left
        data["protocol"] = protocol
        data["valid"] = True
    except ssl.SSLCertVerificationError as e:
        data["has_ssl"] = True
        data["valid"] = False
        data["error"] = str(e)
    except Exception as e:
        data["error"] = str(e)

    return data


def _probe_http(sub: str) -> dict[str, Any]:
    """Quick HTTP check — status code, redirect, server header, response time."""
    data: dict[str, Any] = {
        "reachable": False,
        "status_code": None,
        "redirect": None,
        "server": None,
        "https": False,
        "response_ms": None,
    }
    # Try HTTPS first, then HTTP
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{sub}",
                timeout=5.0,
                allow_redirects=True,
                headers={"User-Agent": "domain-audit/0.1"},
            )
            data["reachable"] = True
            data["status_code"] = resp.status_code
            data["server"] = resp.headers.get("Server", None)
            data["https"] = scheme == "https" or resp.url.startswith("https://")
            data["response_ms"] = round(resp.elapsed.total_seconds() * 1000)
            if resp.url != f"{scheme}://{sub}" and resp.url != f"{scheme}://{sub}/":
                data["redirect"] = resp.url
            break
        except Exception:
            continue

    return data


# ═══════════════════════════════════════════════════════════════════
#  Build summary tables from probe results
# ═══════════════════════════════════════════════════════════════════

def _build_dns_table(probes: list[dict]) -> list[dict[str, str]]:
    """One row per subdomain with IP addresses."""
    rows = []
    for p in probes:
        sub = p["subdomain"]
        dns_data = p["dns"]
        ips = dns_data.get("a", [])
        ipv6 = dns_data.get("aaaa", [])
        cname = dns_data.get("cname", [])

        rows.append({
            "subdomain": sub,
            "a_records": ", ".join(ips) if ips else "-",
            "aaaa_records": ", ".join(ipv6) if ipv6 else "-",
            "cname": ", ".join(cname) if cname else "-",
        })
    return rows


def _build_ssl_table(probes: list[dict]) -> list[dict[str, str]]:
    """One row per subdomain with SSL details."""
    rows = []
    for p in probes:
        sub = p["subdomain"]
        s = p["ssl"]
        ips = p["dns"].get("a", [])

        if s["has_ssl"]:
            grade = "F" if not s["valid"] else (
                "A" if (s["days_left"] or 0) > 90 else
                "B" if (s["days_left"] or 0) > 30 else
                "C" if (s["days_left"] or 0) > 0 else "F"
            )
            rows.append({
                "subdomain": sub,
                "ip": ips[0] if ips else "-",
                "valid": "Yes" if s["valid"] else "No",
                "issuer": s["issuer"] or "-",
                "expires": s["expires"] or "-",
                "days_left": str(s["days_left"]) if s["days_left"] is not None else "-",
                "protocol": s["protocol"] or "-",
                "grade": grade,
            })
        else:
            rows.append({
                "subdomain": sub,
                "ip": ips[0] if ips else "-",
                "valid": "No SSL",
                "issuer": "-",
                "expires": "-",
                "days_left": "-",
                "protocol": "-",
                "grade": "-",
            })
    return rows


def _build_http_table(probes: list[dict]) -> list[dict[str, str]]:
    """One row per subdomain with HTTP reachability + response time."""
    rows = []
    for p in probes:
        sub = p["subdomain"]
        h = p["http"]
        ms = h.get("response_ms")
        rows.append({
            "subdomain": sub,
            "reachable": "Yes" if h["reachable"] else "No",
            "https": "Yes" if h["https"] else "No",
            "status": str(h["status_code"]) if h["status_code"] else "-",
            "server": h["server"] or "-",
            "response_ms": f"{ms}ms" if ms is not None else "-",
            "redirect": h["redirect"] or "-",
        })
    return rows


# ═══════════════════════════════════════════════════════════════════
#  Main scan
# ═══════════════════════════════════════════════════════════════════

def scan(domain: str) -> ScanResult:
    start = time.time()
    raw_data: dict[str, Any] = {}

    try:
        all_subs = _discover_subdomains(domain)
        raw_data["total_discovered"] = len(all_subs)
        raw_data["all_subdomains"] = all_subs

        # Limit how many we scan in detail
        subs_to_scan = all_subs[:MAX_SUBDOMAIN_SCAN]
        raw_data["scanned_count"] = len(subs_to_scan)

        # Probe subdomains in parallel
        probes: list[dict[str, Any]] = []
        if subs_to_scan:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(_probe_subdomain, sub): sub
                    for sub in subs_to_scan
                }
                for future in as_completed(futures):
                    try:
                        probes.append(future.result())
                    except Exception:
                        pass

        # Sort by subdomain name
        probes.sort(key=lambda p: p["subdomain"])
        raw_data["probes"] = probes

        # Build data-type-specific tables
        dns_table = _build_dns_table(probes)
        ssl_table = _build_ssl_table(probes)
        http_table = _build_http_table(probes)

        raw_data["dns_table"] = dns_table
        raw_data["ssl_table"] = ssl_table
        raw_data["http_table"] = http_table

        # Count issues
        ssl_issues = [r for r in ssl_table if r["grade"] in ("C", "F")]
        no_ssl = [r for r in ssl_table if r["valid"] == "No SSL"]
        no_https = [r for r in http_table if r["https"] == "No" and r["reachable"] == "Yes"]

        findings = []

        # Discovery summary
        findings.append({
            "label": "Subdomains discovered",
            "value": all_subs,
            "grade": "-",
            "detail": f"Found {len(all_subs)} subdomain(s) via CT logs, scanned {len(subs_to_scan)} in detail",
            "fix": "",
        })

        # DNS table finding
        findings.append({
            "label": "Subdomain DNS",
            "value": dns_table,
            "grade": "-",
            "detail": f"DNS resolution for {len(dns_table)} subdomain(s)",
            "fix": "",
            "table_type": "dns",
            "table_data": dns_table,
            "domain": domain,
        })

        # SSL table finding
        ssl_grade = "-"
        if ssl_issues:
            ssl_grade = "F" if any(r["grade"] == "F" for r in ssl_issues) else "C"
        findings.append({
            "label": "Subdomain SSL",
            "value": ssl_table,
            "grade": ssl_grade,
            "detail": f"{len(ssl_issues)} SSL issue(s) across {len(ssl_table)} subdomain(s)" if ssl_issues else f"SSL healthy across {len([r for r in ssl_table if r['valid'] not in ('No SSL', '-')])} subdomain(s)",
            "fix": "Review SSL certificates for flagged subdomains" if ssl_issues else "",
            "table_type": "ssl",
            "table_data": ssl_table,
            "domain": domain,
        })

        # HTTP table finding
        http_grade = "-"
        if no_https:
            http_grade = "C"
        findings.append({
            "label": "Subdomain HTTP",
            "value": http_table,
            "grade": http_grade,
            "detail": f"{len(no_https)} subdomain(s) not using HTTPS" if no_https else f"{len([r for r in http_table if r['reachable'] == 'Yes'])} subdomain(s) reachable",
            "fix": "Enable HTTPS on all public-facing subdomains" if no_https else "",
            "table_type": "http",
            "table_data": http_table,
            "domain": domain,
        })

        return ScanResult(
            module="subdomains",
            status="pass",
            grade="-",
            findings=findings,
            raw_data=raw_data,
            elapsed=time.time() - start,
            retries=0,
        )

    except Exception as exc:
        return ScanResult(
            module="subdomains",
            status="error",
            grade="?",
            findings=[{
                "label": "Subdomain discovery",
                "value": f"Error: {exc}",
                "grade": "?",
                "detail": f"CT log query failed: {exc}",
                "fix": "Check network connectivity or try again later",
            }],
            raw_data={"error": str(exc)},
            elapsed=time.time() - start,
            retries=0,
        )
