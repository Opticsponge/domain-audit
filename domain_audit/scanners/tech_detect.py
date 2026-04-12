from __future__ import annotations

import re
import time
from typing import Any

import requests

from domain_audit.grader import ScanResult
from domain_audit.rate_limit import throttle
from domain_audit.retry import RetryConfig, with_retry
from domain_audit.validators import safe_error

_retry = RetryConfig(max_retries=2, timeout_per_attempt=10.0)

# URL paths that indicate specific technologies
TECH_PATHS = {
    "/wp-admin/": "WordPress",
    "/wp-login.php": "WordPress",
    "/wp-content/": "WordPress",
    "/administrator/": "Joomla",
    "/user/login": "Drupal",
    "/sites/default/": "Drupal",
}

# Meta tag patterns
META_PATTERNS = {
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']': "generator",
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']': "generator",
}

# Header patterns
HEADER_TECHS = {
    "X-Powered-By": None,
    "Server": None,
    "X-Drupal-Cache": "Drupal",
    "X-Generator": None,
    "X-AspNet-Version": "ASP.NET",
    "X-Shopify-Stage": "Shopify",
}


@with_retry(config=_retry)
def _fetch_page(domain: str) -> tuple[dict[str, str], str]:
    throttle(f"https://{domain}")
    resp = requests.get(
        f"https://{domain}",
        timeout=_retry.timeout_per_attempt,
        allow_redirects=True,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    return dict(resp.headers), resp.text[:50000]  # limit body size


def scan(domain: str) -> ScanResult:
    start = time.time()
    technologies: list[dict[str, str]] = []
    raw_data: dict[str, Any] = {}

    try:
        headers, body = _fetch_page(domain)
        raw_data["response_headers"] = headers

        # Check headers
        for header_name, tech_name in HEADER_TECHS.items():
            value = next(
                (v for k, v in headers.items() if k.lower() == header_name.lower()),
                None,
            )
            if value:
                tech = tech_name or value.split("/")[0].strip()
                technologies.append({
                    "name": tech,
                    "source": f"Header: {header_name}",
                    "detail": value,
                })

        # Check meta tags
        for pattern, tag_type in META_PATTERNS.items():
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                technologies.append({
                    "name": match.group(1).strip(),
                    "source": f"Meta tag: {tag_type}",
                    "detail": match.group(1).strip(),
                })

        # Check for known URL patterns in page body
        for path, tech_name in TECH_PATHS.items():
            if path in body:
                if not any(t["name"] == tech_name for t in technologies):
                    technologies.append({
                        "name": tech_name,
                        "source": f"URL pattern: {path}",
                        "detail": f"Found {path} reference in page",
                    })

        # Deduplicate by name
        seen = set()
        unique_techs = []
        for tech in technologies:
            if tech["name"].lower() not in seen:
                seen.add(tech["name"].lower())
                unique_techs.append(tech)

        raw_data["technologies"] = unique_techs

        findings = [{
            "label": "Detected technologies",
            "value": [t["name"] for t in unique_techs] if unique_techs else "None detected",
            "grade": "-",
            "detail": ", ".join(t["name"] for t in unique_techs) if unique_techs else "No technologies detected via headers or page content",
            "fix": "",
        }]

        return ScanResult(
            module="tech",
            status="pass",
            grade="-",
            findings=findings,
            raw_data=raw_data,
            elapsed=time.time() - start,
            retries=0,
        )

    except Exception as exc:
        return ScanResult(
            module="tech",
            status="error",
            grade="?",
            findings=[{
                "label": "Technology detection",
                "value": f"Error: {safe_error(exc)}",
                "grade": "?",
                "detail": f"Could not detect technologies: {safe_error(exc)}",
                "fix": "",
            }],
            raw_data={"error": safe_error(exc)},
            elapsed=time.time() - start,
            retries=0,
        )
