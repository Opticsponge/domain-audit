from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import whois

from domain_audit.grader import ScanResult, worst_grade
from domain_audit.retry import RetryConfig, with_retry

_retry = RetryConfig(max_retries=3, timeout_per_attempt=10.0)


@with_retry(config=_retry)
def _whois_lookup(domain: str) -> Any:
    return whois.whois(domain)


def scan(domain: str) -> ScanResult:
    start = time.time()
    retries = 0
    findings = []
    raw_data: dict[str, Any] = {}

    try:
        w = _whois_lookup(domain)

        # Normalize to dict for serialization
        raw_data["registrar"] = w.registrar
        raw_data["creation_date"] = _date_str(w.creation_date)
        raw_data["expiration_date"] = _date_str(w.expiration_date)
        raw_data["name_servers"] = w.name_servers
        raw_data["status"] = w.status

        # Registrar info
        findings.append({
            "label": "Registrar",
            "value": w.registrar or "Unknown",
            "grade": "-",
            "detail": f"Registered with {w.registrar or 'unknown registrar'}",
            "fix": "",
        })

        # Domain expiry
        expiry = _parse_date(w.expiration_date)
        if expiry:
            now = datetime.now(tz=timezone.utc)
            days_left = (expiry - now).days

            if days_left < 0:
                exp_grade = "F"
                exp_detail = f"Domain EXPIRED {abs(days_left)} days ago"
                exp_fix = "Renew your domain registration immediately"
            elif days_left < 30:
                exp_grade = "F"
                exp_detail = f"Domain expires in {days_left} days — urgent renewal needed"
                exp_fix = "Renew your domain registration immediately"
            elif days_left < 90:
                exp_grade = "C"
                exp_detail = f"Domain expires in {days_left} days"
                exp_fix = "Renew your domain registration soon"
            elif days_left < 180:
                exp_grade = "B"
                exp_detail = f"Domain expires in {days_left} days"
                exp_fix = "Plan domain renewal"
            else:
                exp_grade = "A"
                exp_detail = f"Domain valid for {days_left} more days"
                exp_fix = ""

            findings.append({
                "label": "Domain expiration",
                "value": {"expires": _date_str(w.expiration_date), "days_left": days_left},
                "grade": exp_grade,
                "detail": exp_detail,
                "fix": exp_fix,
            })
        else:
            findings.append({
                "label": "Domain expiration",
                "value": "Unknown",
                "grade": "?",
                "detail": "Could not determine domain expiration date",
                "fix": "",
            })

        # Name servers
        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]
        ns = sorted(set(n.lower() for n in ns))
        raw_data["name_servers_clean"] = ns

        findings.append({
            "label": "Name servers",
            "value": ns,
            "grade": "-",
            "detail": f"{len(ns)} name server(s) configured",
            "fix": "",
        })

        grades = [f["grade"] for f in findings if f["grade"] not in ("?", "-")]
        module_grade = worst_grade(grades) if grades else "?"
        status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

        return ScanResult(
            module="whois",
            status=status,
            grade=module_grade,
            findings=findings,
            raw_data=raw_data,
            elapsed=time.time() - start,
            retries=retries,
        )

    except Exception as exc:
        return ScanResult(
            module="whois",
            status="error",
            grade="?",
            findings=[{
                "label": "WHOIS lookup",
                "value": f"Error: {exc}",
                "grade": "?",
                "detail": f"WHOIS lookup failed: {exc}",
                "fix": "Domain may not support WHOIS or the WHOIS server is unreachable",
            }],
            raw_data={"error": str(exc)},
            elapsed=time.time() - start,
            retries=retries,
        )


def _parse_date(date_val: Any) -> datetime | None:
    if isinstance(date_val, list):
        date_val = date_val[0] if date_val else None
    if isinstance(date_val, datetime):
        if date_val.tzinfo is None:
            return date_val.replace(tzinfo=timezone.utc)
        return date_val
    return None


def _date_str(date_val: Any) -> str | None:
    if isinstance(date_val, list):
        date_val = date_val[0] if date_val else None
    if isinstance(date_val, datetime):
        return date_val.isoformat()
    return str(date_val) if date_val else None
