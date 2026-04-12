from __future__ import annotations

import time
from typing import Any

import dns.resolver
import dns.exception

from domain_audit.grader import ScanResult
from domain_audit.retry import RetryConfig, with_retry

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]
CRITICAL_TYPES = {"A", "NS"}
IMPORTANT_TYPES = {"MX", "SOA"}

_retry = RetryConfig(max_retries=3, timeout_per_attempt=5.0)


@with_retry(config=_retry)
def _resolve(domain: str, rdtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rdtype, lifetime=_retry.timeout_per_attempt)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


def scan(domain: str) -> ScanResult:
    start = time.time()
    findings = []
    raw_data: dict[str, Any] = {}
    total_retries = 0

    for rdtype in RECORD_TYPES:
        try:
            records = _resolve(domain, rdtype)
            raw_data[rdtype] = records
            found = len(records) > 0

            grade = "A" if found else _missing_grade(rdtype)
            findings.append({
                "label": f"{rdtype} records",
                "value": records if found else "Not found",
                "grade": grade,
                "detail": f"{'Found' if found else 'Missing'} {rdtype} record{'s' if len(records) != 1 else ''}",
                "fix": _fix_suggestion(rdtype) if not found else "",
            })
        except Exception as exc:
            raw_data[rdtype] = str(exc)
            findings.append({
                "label": f"{rdtype} records",
                "value": f"Error: {exc}",
                "grade": "?",
                "detail": f"Could not query {rdtype}: {exc}",
                "fix": "",
            })

    grades = [f["grade"] for f in findings if f["grade"] not in ("?", "-")]
    module_grade = _worst_grade(grades) if grades else "?"
    status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

    return ScanResult(
        module="dns",
        status=status,
        grade=module_grade,
        findings=findings,
        raw_data=raw_data,
        elapsed=time.time() - start,
        retries=total_retries,
    )


def _missing_grade(rdtype: str) -> str:
    if rdtype in CRITICAL_TYPES:
        return "F"
    if rdtype in IMPORTANT_TYPES:
        return "C"
    return "A"


def _fix_suggestion(rdtype: str) -> str:
    suggestions = {
        "A": "Add an A record pointing to your server's IPv4 address",
        "AAAA": "Consider adding an AAAA record for IPv6 support",
        "MX": "Add MX records to enable email delivery for your domain",
        "NS": "NS records are critical — contact your DNS provider",
        "TXT": "",
        "CNAME": "",
        "SOA": "SOA record should exist — contact your DNS provider",
        "SRV": "",
    }
    return suggestions.get(rdtype, "")


def _worst_grade(grades: list[str]) -> str:
    order = {"F": 0, "C": 1, "B": 2, "A": 3}
    if not grades:
        return "?"
    return min(grades, key=lambda g: order.get(g, -1))
