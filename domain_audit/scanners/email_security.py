from __future__ import annotations

import time
from typing import Any

import dns.resolver
import dns.exception

from domain_audit.grader import ScanResult
from domain_audit.retry import RetryConfig, with_retry

DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "dkim", "mail"]

_retry = RetryConfig(max_retries=3, timeout_per_attempt=5.0)


@with_retry(config=_retry)
def _resolve_txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=_retry.timeout_per_attempt)
        return [str(rdata).strip('"') for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


def scan(domain: str) -> ScanResult:
    start = time.time()
    findings = []
    raw_data: dict[str, Any] = {}

    # SPF check
    txt_records = _resolve_txt(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]
    raw_data["spf"] = spf_records

    if spf_records:
        spf = spf_records[0]
        has_all_fail = "-all" in spf
        has_softfail = "~all" in spf

        if has_all_fail:
            spf_grade = "A"
            spf_detail = "SPF record found with strict policy (-all)"
        elif has_softfail:
            spf_grade = "B"
            spf_detail = "SPF record found but uses soft fail (~all) — consider -all"
        else:
            spf_grade = "C"
            spf_detail = "SPF record found but policy is weak"

        findings.append({
            "label": "SPF record",
            "value": spf,
            "grade": spf_grade,
            "detail": spf_detail,
            "fix": "" if spf_grade == "A" else 'Update SPF to use "-all" instead of "~all"',
        })
    else:
        findings.append({
            "label": "SPF record",
            "value": "Not found",
            "grade": "F",
            "detail": "No SPF record — domain is vulnerable to email spoofing",
            "fix": 'Add a TXT record: v=spf1 include:_spf.google.com -all (adjust for your mail provider)',
        })

    # DMARC check
    dmarc_records = _resolve_txt(f"_dmarc.{domain}")
    dmarc_found = [r for r in dmarc_records if r.startswith("v=DMARC1")]
    raw_data["dmarc"] = dmarc_found

    if dmarc_found:
        dmarc = dmarc_found[0]
        if "p=reject" in dmarc:
            dmarc_grade = "A"
            dmarc_detail = "DMARC record with reject policy — excellent"
        elif "p=quarantine" in dmarc:
            dmarc_grade = "B"
            dmarc_detail = "DMARC record with quarantine policy — consider upgrading to reject"
        elif "p=none" in dmarc:
            dmarc_grade = "C"
            dmarc_detail = "DMARC record with none policy — monitoring only, not enforcing"
        else:
            dmarc_grade = "C"
            dmarc_detail = "DMARC record found but policy unclear"

        findings.append({
            "label": "DMARC record",
            "value": dmarc,
            "grade": dmarc_grade,
            "detail": dmarc_detail,
            "fix": "" if dmarc_grade == "A" else "Upgrade DMARC policy to p=reject after monitoring",
        })
    else:
        findings.append({
            "label": "DMARC record",
            "value": "Not found",
            "grade": "F",
            "detail": "No DMARC record — email authentication not enforced",
            "fix": 'Add TXT record at _dmarc.{domain}: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}'.replace("{domain}", domain),
        })

    # DKIM check
    dkim_found = False
    dkim_selector = None
    for selector in DKIM_SELECTORS:
        dkim_name = f"{selector}._domainkey.{domain}"
        dkim_records = _resolve_txt(dkim_name)
        if dkim_records:
            dkim_found = True
            dkim_selector = selector
            raw_data["dkim"] = {"selector": selector, "records": dkim_records}
            break

    if dkim_found:
        findings.append({
            "label": "DKIM record",
            "value": f"Found (selector: {dkim_selector})",
            "grade": "A",
            "detail": f"DKIM record found with selector '{dkim_selector}'",
            "fix": "",
        })
    else:
        raw_data["dkim"] = {"selectors_checked": DKIM_SELECTORS, "found": False}
        findings.append({
            "label": "DKIM record",
            "value": "Not found",
            "grade": "C",
            "detail": f"No DKIM record found (checked selectors: {', '.join(DKIM_SELECTORS)})",
            "fix": "Configure DKIM signing with your email provider",
        })

    grades = [f["grade"] for f in findings if f["grade"] not in ("?", "-")]
    module_grade = _worst_grade(grades) if grades else "?"
    status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

    return ScanResult(
        module="email",
        status=status,
        grade=module_grade,
        findings=findings,
        raw_data=raw_data,
        elapsed=time.time() - start,
        retries=0,
    )


def _worst_grade(grades: list[str]) -> str:
    order = {"F": 0, "C": 1, "B": 2, "A": 3}
    if not grades:
        return "?"
    return min(grades, key=lambda g: order.get(g, -1))
