from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any, TypedDict

if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired

import httpx

from domain_audit.grader import ScanResult
from domain_audit.rate_limit import throttle
from domain_audit.retry import RetryConfig, with_retry
from domain_audit.validators import safe_error

_retry = RetryConfig(max_retries=2, timeout_per_attempt=10.0)


# ═══════════════════════════════════════════════════════════════════
#  Custom pattern types (JSON/MCP-friendly)
# ═══════════════════════════════════════════════════════════════════


class TechPattern(TypedDict):
    """A single custom detection pattern."""

    pattern: str  # substring (cdn/headers/paths/dns) or regex (asset/inline)
    name: str  # technology name, e.g. "MyInternalCDN"
    category: NotRequired[str]  # display category; defaults to "Other"


class TechPatterns(TypedDict, total=False):
    """Custom patterns to extend built-in tech detection.

    All keys are optional — include only the detection types you need.
    Patterns are additive (extend defaults, never replace).

    Example::

        {
            "cdn_domains": [
                {"pattern": "my-cdn.corp.com", "name": "CorpCDN", "category": "Server / Hosting"}
            ],
            "asset_paths": [
                {"pattern": "my-framework[.\\\\-]", "name": "MyFramework", "category": "Framework / CMS"}
            ],
            "inline_js": [
                {"pattern": "__MY_APP__", "name": "MyApp"}
            ],
            "headers": [
                {"pattern": "X-My-Platform", "name": "", "category": "Server / Hosting"}
            ],
            "paths": [
                {"pattern": "/my-admin/", "name": "MyPlatform"}
            ],
            "dns_txt": [
                {"pattern": "myservice-verification", "name": "MyService"}
            ],
            "dns_cname": [
                {"pattern": ".myplatform.com", "name": "MyPlatform"}
            ]
        }
    """

    cdn_domains: list[TechPattern]
    asset_paths: list[TechPattern]
    inline_js: list[TechPattern]
    headers: list[TechPattern]
    paths: list[TechPattern]
    dns_txt: list[TechPattern]
    dns_cname: list[TechPattern]


_VALID_PATTERN_KEYS = {"cdn_domains", "asset_paths", "inline_js", "headers", "paths", "dns_txt", "dns_cname"}


def _validate_custom_patterns(patterns: dict) -> None:
    """Raise ValueError for malformed custom patterns."""
    for key in patterns:
        if key not in _VALID_PATTERN_KEYS:
            raise ValueError(f"Unknown pattern type: {key!r}. Valid: {', '.join(sorted(_VALID_PATTERN_KEYS))}")
        if not isinstance(patterns[key], list):
            raise ValueError(f"tech_patterns[{key!r}] must be a list")
        for i, entry in enumerate(patterns[key]):
            if "pattern" not in entry or "name" not in entry:
                raise ValueError(f"tech_patterns[{key!r}][{i}] must have 'pattern' and 'name' keys")
            if key in ("asset_paths", "inline_js"):
                try:
                    re.compile(entry["pattern"])
                except re.error as e:
                    raise ValueError(f"tech_patterns[{key!r}][{i}] invalid regex: {e}") from e


# ═══════════════════════════════════════════════════════════════════
#  Load patterns from JSON files
#
#  Each file in tech_patterns/ is a standalone JSON array of
#  {pattern, name} objects. Edit those files to add new detections.
# ═══════════════════════════════════════════════════════════════════

_PATTERNS_DIR = Path(__file__).parent / "tech_patterns"


def _load_json(filename: str) -> list[dict[str, str]]:
    with open(_PATTERNS_DIR / filename) as f:
        return json.load(f)


def _load_tuples(filename: str) -> list[tuple[str, str]]:
    """Load JSON array of {pattern, name} into list of (pattern, name) tuples."""
    return [(e["pattern"], e["name"]) for e in _load_json(filename)]


def _load_dict(filename: str) -> dict[str, str | None]:
    """Load JSON array of {pattern, name} into a dict. Empty name → None."""
    return {e["pattern"]: (e["name"] or None) for e in _load_json(filename)}


def _load_categories() -> tuple[dict[str, set[str]], dict[str, str]]:
    """Load categories.json and build both the map and the inverted lookup."""
    with open(_PATTERNS_DIR / "categories.json") as f:
        raw = json.load(f)
    cat_map = {k: set(v) for k, v in raw.items()}
    tech_to_cat: dict[str, str] = {}
    for cat, techs in cat_map.items():
        for t in techs:
            tech_to_cat[t] = cat
    return cat_map, tech_to_cat


# Load all patterns at import time (cached for performance)
CDN_DOMAIN_MAP = _load_tuples("cdn_domains.json")
ASSET_PATH_PATTERNS = _load_tuples("asset_paths.json")
INLINE_JS_PATTERNS = _load_tuples("inline_js.json")
DNS_TXT_PATTERNS = _load_tuples("dns_txt.json")
DNS_CNAME_PATTERNS = _load_tuples("dns_cname.json")
HEADER_TECHS = _load_dict("headers.json")
TECH_PATHS = _load_dict("paths.json")
META_PATTERNS = _load_dict("meta_tags.json")
_CATEGORY_MAP, _TECH_TO_CATEGORY = _load_categories()


# ═══════════════════════════════════════════════════════════════════
#  Extraction helpers
# ═══════════════════════════════════════════════════════════════════

_SRC_RE = re.compile(
    r"""<(?:script|link|img)[^>]+(?:src|href)\s*=\s*["\']([^"\']+)["\']""",
    re.IGNORECASE,
)


def _extract_asset_urls(html: str) -> list[str]:
    return _SRC_RE.findall(html)


def _detect_from_assets(
    urls: list[str],
    cdn_map: list[tuple[str, str]],
    asset_patterns: list[tuple[str, str]],
) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for url in urls:
        url_lower = url.lower()
        for domain_pattern, tech in cdn_map:
            if domain_pattern in url_lower and tech.lower() not in seen:
                seen.add(tech.lower())
                hits.append({"name": tech, "source": f"CDN domain: {domain_pattern}", "detail": _trunc(url)})
        for pattern, tech in asset_patterns:
            if tech.lower() not in seen and re.search(pattern, url_lower):
                seen.add(tech.lower())
                hits.append({"name": tech, "source": "Asset URL pattern", "detail": _trunc(url)})
    return hits


def _detect_from_inline_js(
    html: str,
    js_patterns: list[tuple[str, str]],
) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for pattern, tech in js_patterns:
        if tech.lower() not in seen and re.search(pattern, html):
            seen.add(tech.lower())
            hits.append({"name": tech, "source": "Inline JS marker", "detail": pattern.replace("\\", "")})
    return hits


def _detect_from_dns(
    domain: str,
    txt_patterns: list[tuple[str, str]],
    cname_patterns: list[tuple[str, str]],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    import dns.exception
    import dns.resolver

    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    raw: dict[str, Any] = {}

    # TXT records
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        txt_records = [r.to_text().strip('"') for r in answers]
        raw["txt_records"] = txt_records
        for record in txt_records:
            record_lower = record.lower()
            for pattern, tech in txt_patterns:
                if pattern.lower() in record_lower and tech.lower() not in seen:
                    seen.add(tech.lower())
                    hits.append({"name": tech, "source": "DNS TXT record", "detail": _trunc(record)})
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        raw["txt_records"] = []

    # CNAME record
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        cname_targets = [r.to_text().rstrip(".") for r in answers]
        raw["cname_targets"] = cname_targets
        for target in cname_targets:
            target_lower = target.lower()
            for pattern, tech in cname_patterns:
                if pattern in target_lower and tech.lower() not in seen:
                    seen.add(tech.lower())
                    hits.append({"name": tech, "source": "DNS CNAME target", "detail": target})
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        raw["cname_targets"] = []

    return hits, raw


def _categorize(
    techs: list[dict[str, str]],
    extra_categories: dict[str, str] | None = None,
) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = {}
    for tech in techs:
        key = tech["name"].lower()
        cat = _TECH_TO_CATEGORY.get(key)
        if cat is None and extra_categories:
            cat = extra_categories.get(key)
        groups.setdefault(cat or "Other", []).append(tech)
    return groups


def _trunc(url: str, max_len: int = 120) -> str:
    return url if len(url) <= max_len else url[:max_len] + "..."


# ═══════════════════════════════════════════════════════════════════
#  Pattern merging
# ═══════════════════════════════════════════════════════════════════


class _EffectivePatterns:
    __slots__ = ("cdn", "asset", "inline", "headers", "paths", "dns_txt", "dns_cname", "extra_categories")

    def __init__(self) -> None:
        self.cdn = list(CDN_DOMAIN_MAP)
        self.asset = list(ASSET_PATH_PATTERNS)
        self.inline = list(INLINE_JS_PATTERNS)
        self.headers = dict(HEADER_TECHS)
        self.paths = dict(TECH_PATHS)
        self.dns_txt = list(DNS_TXT_PATTERNS)
        self.dns_cname = list(DNS_CNAME_PATTERNS)
        self.extra_categories: dict[str, str] = {}


def _merge_patterns(custom_patterns: dict | None) -> _EffectivePatterns:
    eff = _EffectivePatterns()
    if not custom_patterns:
        return eff

    _validate_custom_patterns(custom_patterns)

    def _add(name: str, entry: dict) -> None:
        if "category" in entry and name:
            eff.extra_categories[name.lower()] = entry["category"]

    for p in custom_patterns.get("cdn_domains", []):
        eff.cdn.append((p["pattern"], p["name"]))
        _add(p["name"], p)
    for p in custom_patterns.get("asset_paths", []):
        eff.asset.append((p["pattern"], p["name"]))
        _add(p["name"], p)
    for p in custom_patterns.get("inline_js", []):
        eff.inline.append((p["pattern"], p["name"]))
        _add(p["name"], p)
    for p in custom_patterns.get("headers", []):
        eff.headers[p["pattern"]] = p["name"] or None
        _add(p["name"], p)
    for p in custom_patterns.get("paths", []):
        eff.paths[p["pattern"]] = p["name"]
        _add(p["name"], p)
    for p in custom_patterns.get("dns_txt", []):
        eff.dns_txt.append((p["pattern"], p["name"]))
        _add(p["name"], p)
    for p in custom_patterns.get("dns_cname", []):
        eff.dns_cname.append((p["pattern"], p["name"]))
        _add(p["name"], p)

    return eff


# ═══════════════════════════════════════════════════════════════════
#  Main scan
# ═══════════════════════════════════════════════════════════════════


@with_retry(config=_retry)
def _fetch_page(domain: str) -> tuple[dict[str, str], str]:
    throttle(f"https://{domain}")
    resp = httpx.get(
        f"https://{domain}",
        timeout=_retry.timeout_per_attempt,
        follow_redirects=True,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    return dict(resp.headers), resp.text[:100000]


def scan(domain: str, custom_patterns: dict | None = None) -> ScanResult:
    start = time.time()
    technologies: list[dict[str, str]] = []
    raw_data: dict[str, Any] = {}

    eff = _merge_patterns(custom_patterns)

    # 1. DNS records (independent of HTTP)
    try:
        dns_hits, dns_raw = _detect_from_dns(domain, eff.dns_txt, eff.dns_cname)
        technologies.extend(dns_hits)
        raw_data["dns_detection"] = dns_raw
    except Exception:
        raw_data["dns_detection"] = {"error": "DNS query failed"}

    try:
        headers, body = _fetch_page(domain)
        raw_data["response_headers"] = headers

        # 2. Response headers
        for header_name, tech_name in eff.headers.items():
            value = next(
                (v for k, v in headers.items() if k.lower() == header_name.lower()),
                None,
            )
            if value:
                tech = tech_name or value.split("/")[0].strip()
                technologies.append({"name": tech, "source": f"Header: {header_name}", "detail": value})

        # 3. Meta tags
        for pattern, tag_type in META_PATTERNS.items():
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                technologies.append(
                    {
                        "name": match.group(1).strip(),
                        "source": f"Meta tag: {tag_type}",
                        "detail": match.group(1).strip(),
                    }
                )

        # 4. URL paths in body
        for path, tech_name in eff.paths.items():
            if tech_name and path in body and not any(t["name"] == tech_name for t in technologies):
                technologies.append(
                    {"name": tech_name, "source": f"URL pattern: {path}", "detail": f"Found {path} reference in page"}
                )

        # 5. Asset URL fingerprinting
        asset_urls = _extract_asset_urls(body)
        raw_data["asset_urls_scanned"] = len(asset_urls)
        technologies.extend(_detect_from_assets(asset_urls, eff.cdn, eff.asset))

        # 6. Inline JS markers
        technologies.extend(_detect_from_inline_js(body, eff.inline))

        # Deduplicate
        seen: set[str] = set()
        unique_techs: list[dict[str, str]] = []
        for tech in technologies:
            key = tech["name"].lower()
            if key not in seen:
                seen.add(key)
                unique_techs.append(tech)

        raw_data["technologies"] = unique_techs
        if custom_patterns:
            raw_data["custom_patterns_applied"] = True

        categories = _categorize(unique_techs, eff.extra_categories)
        findings: list[dict[str, Any]] = []

        for category, techs in categories.items():
            names = ", ".join(t["name"] for t in techs)
            findings.append(
                {"label": category, "value": [t["name"] for t in techs], "grade": "-", "detail": names, "fix": ""}
            )

        if not findings:
            findings.append(
                {
                    "label": "Detected technologies",
                    "value": "None detected",
                    "grade": "-",
                    "detail": f"No technologies detected (scanned {len(asset_urls)} asset URLs)",
                    "fix": "",
                }
            )

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
            findings=[
                {
                    "label": "Technology detection",
                    "value": f"Error: {safe_error(exc)}",
                    "grade": "?",
                    "detail": f"Could not detect technologies: {safe_error(exc)}",
                    "fix": "",
                }
            ],
            raw_data={"error": safe_error(exc)},
            elapsed=time.time() - start,
            retries=0,
        )
