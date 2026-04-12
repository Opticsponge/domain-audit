from __future__ import annotations

import contextlib
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.resolver
import requests

from domain_audit.grader import ScanResult
from domain_audit.rate_limit import throttle
from domain_audit.retry import RetryConfig
from domain_audit.validators import is_private_ip, safe_error

_retry_ct = RetryConfig(max_retries=3, base_delay=2.0, timeout_per_attempt=15.0)
_retry_dns = RetryConfig(max_retries=2, timeout_per_attempt=5.0)

# Max subdomains to scan in detail (avoid hammering hundreds)
MAX_SUBDOMAIN_SCAN = 25


def _query_crtsh(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh Certificate Transparency logs."""
    throttle("https://crt.sh/")
    resp = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=15.0,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    resp.raise_for_status()
    return resp.json()


def _query_certspotter(domain: str) -> list[dict[str, Any]]:
    """Fallback: query SSLMate's Cert Spotter API."""
    throttle("https://api.certspotter.com/")
    resp = requests.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=15.0,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    resp.raise_for_status()
    return resp.json()


def _discover_subdomains(domain: str) -> list[str]:
    """Discover subdomains via CT logs. Tries crt.sh first, falls back to Cert Spotter."""
    subdomains: set[str] = set()

    # Try crt.sh first
    try:
        entries = _query_crtsh(domain)
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*") and (name.endswith(f".{domain}") or name == domain):
                    subdomains.add(name)
        if subdomains:
            return sorted(subdomains)
    except Exception:
        pass  # Fall through to backup

    # Fallback: Cert Spotter
    try:
        entries = _query_certspotter(domain)
        for entry in entries:
            for name in entry.get("dns_names", []):
                name = name.strip().lower()
                if name and not name.startswith("*") and (name.endswith(f".{domain}") or name == domain):
                    subdomains.add(name)
        if subdomains:
            return sorted(subdomains)
    except Exception:
        pass

    # If both fail, try basic DNS brute-force with common prefixes
    common_prefixes = [
        "www",
        "mail",
        "ftp",
        "smtp",
        "pop",
        "imap",
        "blog",
        "webmail",
        "server",
        "ns1",
        "ns2",
        "dns",
        "dns1",
        "dns2",
        "mx",
        "mx1",
        "vpn",
        "admin",
        "portal",
        "api",
        "dev",
        "staging",
        "test",
        "app",
        "cdn",
        "cloud",
        "git",
        "ssh",
        "remote",
        "cpanel",
    ]
    for prefix in common_prefixes:
        sub = f"{prefix}.{domain}"
        try:
            dns.resolver.resolve(sub, "A", lifetime=2.0)
            subdomains.add(sub)
        except Exception:
            pass

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
        # Resolve first to reject private IPs
        resolved_ip = socket.gethostbyname(sub)
        if is_private_ip(resolved_ip):
            data["error"] = "Skipped: resolves to private/reserved IP"
            return data
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
    # Skip subdomains that resolve to private IPs
    try:
        resolved_ip = socket.gethostbyname(sub)
        if is_private_ip(resolved_ip):
            data["error"] = "Skipped: resolves to private/reserved IP"
            return data
    except socket.gaierror:
        return data

    # Try HTTPS first, then HTTP
    for scheme in ("https", "http"):
        try:
            throttle(f"{scheme}://{sub}")
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

        rows.append(
            {
                "subdomain": sub,
                "a_records": ", ".join(ips) if ips else "-",
                "aaaa_records": ", ".join(ipv6) if ipv6 else "-",
                "cname": ", ".join(cname) if cname else "-",
            }
        )
    return rows


def _build_ssl_table(probes: list[dict]) -> list[dict[str, str]]:
    """One row per subdomain with SSL details."""
    rows = []
    for p in probes:
        sub = p["subdomain"]
        s = p["ssl"]
        ips = p["dns"].get("a", [])

        if s["has_ssl"]:
            grade = (
                "F"
                if not s["valid"]
                else (
                    "A"
                    if (s["days_left"] or 0) > 90
                    else "B"
                    if (s["days_left"] or 0) > 30
                    else "C"
                    if (s["days_left"] or 0) > 0
                    else "F"
                )
            )
            rows.append(
                {
                    "subdomain": sub,
                    "ip": ips[0] if ips else "-",
                    "valid": "Yes" if s["valid"] else "No",
                    "issuer": s["issuer"] or "-",
                    "expires": s["expires"] or "-",
                    "days_left": str(s["days_left"]) if s["days_left"] is not None else "-",
                    "protocol": s["protocol"] or "-",
                    "grade": grade,
                }
            )
        else:
            rows.append(
                {
                    "subdomain": sub,
                    "ip": ips[0] if ips else "-",
                    "valid": "No SSL",
                    "issuer": "-",
                    "expires": "-",
                    "days_left": "-",
                    "protocol": "-",
                    "grade": "-",
                }
            )
    return rows


def _build_http_table(probes: list[dict]) -> list[dict[str, str]]:
    """One row per subdomain with HTTP reachability + response time."""
    rows = []
    for p in probes:
        sub = p["subdomain"]
        h = p["http"]
        ms = h.get("response_ms")
        rows.append(
            {
                "subdomain": sub,
                "reachable": "Yes" if h["reachable"] else "No",
                "https": "Yes" if h["https"] else "No",
                "status": str(h["status_code"]) if h["status_code"] else "-",
                "server": h["server"] or "-",
                "response_ms": f"{ms}ms" if ms is not None else "-",
                "redirect": h["redirect"] or "-",
            }
        )
    return rows


# ═══════════════════════════════════════════════════════════════════
#  Main scan
# ═══════════════════════════════════════════════════════════════════


def scan(domain: str, deep: bool = False) -> ScanResult:
    """Scan subdomains. deep=True probes each subdomain for DNS/SSL/HTTP (slower)."""
    start = time.time()
    raw_data: dict[str, Any] = {}

    try:
        all_subs = _discover_subdomains(domain)
        raw_data["total_discovered"] = len(all_subs)
        raw_data["all_subdomains"] = all_subs

        # Deep mode: probe each subdomain for DNS/SSL/HTTP
        probes: list[dict[str, Any]] = []
        if deep:
            subs_to_scan = all_subs[:MAX_SUBDOMAIN_SCAN]
            raw_data["scanned_count"] = len(subs_to_scan)

            if subs_to_scan:
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {executor.submit(_probe_subdomain, sub): sub for sub in subs_to_scan}
                    for future in as_completed(futures):
                        with contextlib.suppress(Exception):
                            probes.append(future.result())
        else:
            raw_data["scanned_count"] = 0

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
        no_https = [r for r in http_table if r["https"] == "No" and r["reachable"] == "Yes"]

        findings = []

        # Discovery summary
        scanned_count = raw_data["scanned_count"]
        detail_msg = f"Found {len(all_subs)} subdomain(s) via CT logs"
        if deep:
            detail_msg += f", scanned {scanned_count} in detail"
        else:
            detail_msg += " (use deep=True to probe each subdomain)"

        findings.append(
            {
                "label": "Subdomains discovered",
                "value": all_subs,
                "grade": "-",
                "detail": detail_msg,
                "fix": "",
                "subdomain_list": all_subs,
            }
        )

        # Only add detail tables if deep mode was used
        if not probes:
            return ScanResult(
                module="subdomains",
                status="pass",
                grade="-",
                findings=findings,
                raw_data=raw_data,
                elapsed=time.time() - start,
                retries=0,
            )

        # DNS table finding
        findings.append(
            {
                "label": "Subdomain DNS",
                "value": dns_table,
                "grade": "-",
                "detail": f"DNS resolution for {len(dns_table)} subdomain(s)",
                "fix": "",
                "table_type": "dns",
                "table_data": dns_table,
                "domain": domain,
            }
        )

        # SSL table finding
        ssl_grade = "-"
        if ssl_issues:
            ssl_grade = "F" if any(r["grade"] == "F" for r in ssl_issues) else "C"
        findings.append(
            {
                "label": "Subdomain SSL",
                "value": ssl_table,
                "grade": ssl_grade,
                "detail": f"{len(ssl_issues)} SSL issue(s) across {len(ssl_table)} subdomain(s)"
                if ssl_issues
                else f"SSL healthy across {len([r for r in ssl_table if r['valid'] not in ('No SSL', '-')])} subdomain(s)",
                "fix": "Review SSL certificates for flagged subdomains" if ssl_issues else "",
                "table_type": "ssl",
                "table_data": ssl_table,
                "domain": domain,
            }
        )

        # HTTP table finding
        http_grade = "-"
        if no_https:
            http_grade = "C"
        findings.append(
            {
                "label": "Subdomain HTTP",
                "value": http_table,
                "grade": http_grade,
                "detail": f"{len(no_https)} subdomain(s) not using HTTPS"
                if no_https
                else f"{len([r for r in http_table if r['reachable'] == 'Yes'])} subdomain(s) reachable",
                "fix": "Enable HTTPS on all public-facing subdomains" if no_https else "",
                "table_type": "http",
                "table_data": http_table,
                "domain": domain,
            }
        )

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
            grade="C",
            findings=[
                {
                    "label": "Subdomain discovery failed",
                    "value": f"Error: {safe_error(exc)}",
                    "grade": "C",
                    "detail": f"Could not discover subdomains — all CT log sources failed: {safe_error(exc)}",
                    "fix": "Subdomain enumeration is incomplete. Try again or check network connectivity. CT log services (crt.sh, Cert Spotter) may be rate-limiting this IP.",
                }
            ],
            raw_data={"error": safe_error(exc)},
            elapsed=time.time() - start,
            retries=0,
        )
