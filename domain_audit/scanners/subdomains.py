from __future__ import annotations

import re
import time
from typing import Any

import requests

from domain_audit.grader import ScanResult
from domain_audit.retry import RetryConfig, with_retry

_retry = RetryConfig(max_retries=3, base_delay=2.0, timeout_per_attempt=15.0)


@with_retry(config=_retry)
def _query_crtsh(domain: str) -> list[dict[str, Any]]:
    resp = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=_retry.timeout_per_attempt,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    resp.raise_for_status()
    return resp.json()


def scan(domain: str) -> ScanResult:
    start = time.time()
    retries = 0
    subdomains: set[str] = set()
    raw_data: dict[str, Any] = {}

    try:
        entries = _query_crtsh(domain)
        raw_data["crtsh_count"] = len(entries)

        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*") and name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name)

        sorted_subs = sorted(subdomains)
        raw_data["subdomains"] = sorted_subs

        findings = [{
            "label": "Subdomains discovered",
            "value": sorted_subs,
            "grade": "-",
            "detail": f"Found {len(sorted_subs)} unique subdomain(s) via Certificate Transparency logs",
            "fix": "",
        }]

        return ScanResult(
            module="subdomains",
            status="pass",
            grade="-",
            findings=findings,
            raw_data=raw_data,
            elapsed=time.time() - start,
            retries=retries,
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
            retries=retries,
        )
