from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from domain_audit.grader import ScanResult, worst_grade
from domain_audit.retry import RetryConfig, with_retry
from domain_audit.validators import safe_error

_retry = RetryConfig(max_retries=3, timeout_per_attempt=10.0)


@with_retry(config=_retry)
def _get_cert(domain: str, port: int = 443) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
        sock.settimeout(_retry.timeout_per_attempt)
        sock.connect((domain, port))
        cert = sock.getpeercert()
        protocol = sock.version()
    return {"cert": cert, "protocol": protocol}


def scan(domain: str) -> ScanResult:
    start = time.time()
    retries = 0
    findings = []
    raw_data: dict[str, Any] = {}

    try:
        info = _get_cert(domain)
        cert = info["cert"]
        protocol = info["protocol"]
        raw_data = info

        # Expiration check
        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        expiry_dt = ssl.cert_time_to_seconds(not_after)
        expiry_date = datetime.fromtimestamp(expiry_dt, tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        days_left = (expiry_date - now).days

        # Detect short-lived certificates (total validity <= 90 days)
        short_lived = False
        if not_before:
            issued_dt = ssl.cert_time_to_seconds(not_before)
            issued_date = datetime.fromtimestamp(issued_dt, tz=timezone.utc)
            total_validity = (expiry_date - issued_date).days
            short_lived = total_validity <= 90

        if days_left < 0:
            exp_grade = "F"
            exp_detail = f"Certificate EXPIRED {abs(days_left)} days ago"
        elif days_left < 15:
            exp_grade = "F"
            exp_detail = f"Certificate expires in {days_left} days — imminent outage risk"
        elif days_left < 30:
            exp_grade = "C"
            exp_detail = f"Certificate expires in {days_left} days — renew immediately"
        elif short_lived:
            exp_grade = "A"
            exp_detail = (
                f"Short-lived certificate ({total_validity}d validity), {days_left} days remaining — auto-rotated"
            )
        elif days_left < 60:
            exp_grade = "B"
            exp_detail = f"Certificate expires in {days_left} days — schedule renewal"
        else:
            exp_grade = "A"
            exp_detail = f"Certificate valid for {days_left} more days"

        findings.append(
            {
                "label": "Certificate expiration",
                "value": {"expires": not_after, "days_left": days_left},
                "grade": exp_grade,
                "detail": exp_detail,
                "fix": "" if exp_grade == "A" else "Renew your SSL certificate",
            }
        )

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        raw_data["issuer"] = issuer
        findings.append(
            {
                "label": "Certificate issuer",
                "value": issuer.get("organizationName", "Unknown"),
                "grade": "-",
                "detail": f"Issued by {issuer.get('organizationName', 'Unknown')}",
                "fix": "",
            }
        )

        # Subject Alternative Names
        sans = [entry[1] for entry in cert.get("subjectAltName", [])]
        raw_data["sans"] = sans
        hostname_match = any(_hostname_matches(domain, san) for san in sans)

        if hostname_match:
            match_grade = "A"
            match_detail = "Certificate hostname matches domain"
        else:
            match_grade = "F"
            match_detail = f"Certificate does NOT match {domain} — SANs: {sans}"

        findings.append(
            {
                "label": "Hostname match",
                "value": {"match": hostname_match, "sans": sans},
                "grade": match_grade,
                "detail": match_detail,
                "fix": "Get a certificate that covers this domain" if not hostname_match else "",
            }
        )

        # Protocol version
        weak_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
        if protocol in weak_protocols:
            proto_grade = "F"
            proto_detail = f"Using deprecated protocol {protocol}"
            proto_fix = "Disable TLS 1.0/1.1 and use TLS 1.2+ on your server"
        else:
            proto_grade = "A"
            proto_detail = f"Using {protocol}"
            proto_fix = ""

        findings.append(
            {
                "label": "Protocol version",
                "value": protocol,
                "grade": proto_grade,
                "detail": proto_detail,
                "fix": proto_fix,
            }
        )

        grades = [str(f["grade"]) for f in findings if f["grade"] not in ("?", "-")]
        module_grade = worst_grade(grades) if grades else "?"
        status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

        return ScanResult(
            module="ssl",
            status=status,
            grade=module_grade,
            findings=findings,
            raw_data=raw_data,
            elapsed=time.time() - start,
            retries=retries,
        )

    except Exception as exc:
        return ScanResult(
            module="ssl",
            status="error",
            grade="?",
            findings=[
                {
                    "label": "SSL/TLS connection",
                    "value": f"Error: {safe_error(exc)}",
                    "grade": "?",
                    "detail": f"Could not establish SSL connection: {safe_error(exc)}",
                    "fix": "Verify the domain has SSL/TLS enabled on port 443",
                }
            ],
            raw_data={"error": safe_error(exc)},
            elapsed=time.time() - start,
            retries=retries,
        )


def _hostname_matches(domain: str, san: str) -> bool:
    if san.startswith("*."):
        wildcard_base = san[2:]
        return domain == wildcard_base or domain.endswith(f".{wildcard_base}")
    return domain == san
