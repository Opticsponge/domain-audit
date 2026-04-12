from __future__ import annotations

import time
from typing import Any

import requests

from domain_audit.grader import ScanResult
from domain_audit.retry import RetryConfig, with_retry

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "label": "HSTS (Strict-Transport-Security)",
        "severity": "HIGH",
        "fix": 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
    },
    "Content-Security-Policy": {
        "label": "Content-Security-Policy",
        "severity": "HIGH",
        "fix": "Add a Content-Security-Policy header to prevent XSS and data injection",
    },
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

_retry = RetryConfig(max_retries=2, timeout_per_attempt=10.0)


@with_retry(config=_retry)
def _fetch_headers(domain: str) -> dict[str, str]:
    resp = requests.get(
        f"https://{domain}",
        timeout=_retry.timeout_per_attempt,
        allow_redirects=True,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    return dict(resp.headers)


def scan(domain: str) -> ScanResult:
    start = time.time()
    retries = 0
    findings = []
    raw_data: dict[str, Any] = {}

    try:
        response_headers = _fetch_headers(domain)
        raw_data["headers"] = response_headers
        present_count = 0

        for header_name, meta in SECURITY_HEADERS.items():
            found = header_name.lower() in {k.lower(): v for k, v in response_headers.items()}
            header_value = next(
                (v for k, v in response_headers.items() if k.lower() == header_name.lower()),
                None,
            )

            if found:
                present_count += 1
                grade = "A"
                detail = f"{meta['label']} is set"
            else:
                grade = "C" if meta["severity"] in ("HIGH",) else "B"
                detail = f"{meta['label']} is missing"

            findings.append({
                "label": meta["label"],
                "value": header_value or "Not set",
                "grade": grade,
                "detail": detail,
                "fix": "" if found else meta["fix"],
            })

        total = len(SECURITY_HEADERS)
        if present_count == total:
            module_grade = "A"
        elif present_count >= total - 1:
            module_grade = "B"
        elif present_count >= total // 2:
            module_grade = "C"
        else:
            module_grade = "F"

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
            findings=[{
                "label": "HTTP Security Headers",
                "value": f"Error: {exc}",
                "grade": "?",
                "detail": f"Could not fetch headers: {exc}",
                "fix": "Verify the domain responds to HTTPS requests",
            }],
            raw_data={"error": str(exc)},
            elapsed=time.time() - start,
            retries=retries,
        )
