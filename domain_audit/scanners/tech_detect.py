from __future__ import annotations

import re
import time
from typing import Any, TypedDict, NotRequired

import requests

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
    pattern: str                    # substring (cdn/headers/paths) or regex (asset/inline)
    name: str                       # technology name, e.g. "MyInternalCDN"
    category: NotRequired[str]      # display category; defaults to "Other"


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
            ]
        }
    """
    cdn_domains: list[TechPattern]      # matched as substring in asset URLs
    asset_paths: list[TechPattern]      # matched as regex against asset URLs
    inline_js: list[TechPattern]        # matched as regex against page HTML
    headers: list[TechPattern]          # pattern = header name; empty name → use header value
    paths: list[TechPattern]            # pattern = URL path substring to find in body


_VALID_PATTERN_KEYS = {"cdn_domains", "asset_paths", "inline_js", "headers", "paths"}


def _validate_custom_patterns(patterns: dict) -> None:
    """Raise ValueError for malformed custom patterns."""
    for key in patterns:
        if key not in _VALID_PATTERN_KEYS:
            raise ValueError(f"Unknown pattern type: {key!r}. Valid: {', '.join(sorted(_VALID_PATTERN_KEYS))}")
        if not isinstance(patterns[key], list):
            raise ValueError(f"tech_patterns[{key!r}] must be a list")
        for i, entry in enumerate(patterns[key]):
            if "pattern" not in entry or "name" not in entry:
                raise ValueError(
                    f"tech_patterns[{key!r}][{i}] must have 'pattern' and 'name' keys"
                )
            # Validate regex patterns compile
            if key in ("asset_paths", "inline_js"):
                try:
                    re.compile(entry["pattern"])
                except re.error as e:
                    raise ValueError(
                        f"tech_patterns[{key!r}][{i}] invalid regex: {e}"
                    ) from e


# ═══════════════════════════════════════════════════════════════════
#  URL path probes (classic CMS detection)
# ═══════════════════════════════════════════════════════════════════

TECH_PATHS = {
    "/wp-admin/": "WordPress",
    "/wp-login.php": "WordPress",
    "/wp-content/": "WordPress",
    "/administrator/": "Joomla",
    "/user/login": "Drupal",
    "/sites/default/": "Drupal",
}

# ═══════════════════════════════════════════════════════════════════
#  Response header fingerprints
# ═══════════════════════════════════════════════════════════════════

META_PATTERNS = {
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']': "generator",
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']': "generator",
}

HEADER_TECHS = {
    "X-Powered-By": None,
    "Server": None,
    "X-Drupal-Cache": "Drupal",
    "X-Generator": None,
    "X-AspNet-Version": "ASP.NET",
    "X-Shopify-Stage": "Shopify",
}

# ═══════════════════════════════════════════════════════════════════
#  CDN / hosting domain → platform mapping
# ═══════════════════════════════════════════════════════════════════

CDN_DOMAIN_MAP: list[tuple[str, str]] = [
    # Website builders / CMS platforms
    ("website-files.com", "Webflow"),
    ("webflow.com", "Webflow"),
    ("cdn.shopify.com", "Shopify"),
    ("shopifycdn.com", "Shopify"),
    ("squarespace.com", "Squarespace"),
    ("sqspcdn.com", "Squarespace"),
    ("wixstatic.com", "Wix"),
    ("parastorage.com", "Wix"),
    ("ghost.io", "Ghost"),
    ("ghost.org", "Ghost"),
    ("hubspot.com", "HubSpot"),
    ("hubspot.net", "HubSpot"),
    ("hs-scripts.com", "HubSpot"),
    ("hsforms.com", "HubSpot"),
    ("contentful.com", "Contentful"),
    ("prismic.io", "Prismic"),
    ("sanity.io", "Sanity"),
    ("storyblok.com", "Storyblok"),
    ("framer.com", "Framer"),
    ("webnode.com", "Webnode"),
    ("godaddy.com", "GoDaddy"),
    ("carrd.co", "Carrd"),

    # Hosting / infrastructure
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("vercel.app", "Vercel"),
    ("vercel.com", "Vercel"),
    ("herokuapp.com", "Heroku"),
    ("cloudflare.com", "Cloudflare"),
    ("cloudflareinsights.com", "Cloudflare"),
    ("cdn-cgi/", "Cloudflare"),
    ("amazonaws.com", "AWS"),
    ("cloudfront.net", "AWS CloudFront"),
    ("azurewebsites.net", "Azure"),
    ("azureedge.net", "Azure CDN"),
    ("azure.com", "Azure"),
    ("googleusercontent.com", "Google Cloud"),
    ("googleapis.com", "Google Cloud"),
    ("firebase.com", "Firebase"),
    ("firebaseapp.com", "Firebase"),
    ("firebaseio.com", "Firebase"),
    ("fastly.net", "Fastly"),
    ("akamaized.net", "Akamai"),
    ("akamai.net", "Akamai"),
    ("edgecastcdn.net", "Edgecast"),
    ("stackpathdns.com", "StackPath"),
    ("digitaloceanspaces.com", "DigitalOcean"),
    ("pages.dev", "Cloudflare Pages"),
    ("workers.dev", "Cloudflare Workers"),
    ("fly.dev", "Fly.io"),
    ("render.com", "Render"),
    ("railway.app", "Railway"),
    ("supabase.co", "Supabase"),
    ("supabase.com", "Supabase"),
]

# ═══════════════════════════════════════════════════════════════════
#  JS / CSS filename → framework / library detection
# ═══════════════════════════════════════════════════════════════════

ASSET_PATH_PATTERNS: list[tuple[str, str]] = [
    # Frameworks
    (r"[/.]react[.\-]", "React"),
    (r"react[-.]dom", "React"),
    (r"[/.]vue[.\-]", "Vue.js"),
    (r"[/.]angular[.\-/]", "Angular"),
    (r"[/.]svelte[.\-/]", "Svelte"),
    (r"[/.]next[/.\-]", "Next.js"),
    (r"/_next/", "Next.js"),
    (r"[/.]nuxt[.\-/]", "Nuxt.js"),
    (r"/_nuxt/", "Nuxt.js"),
    (r"[/.]gatsby[.\-/]", "Gatsby"),
    (r"[/.]remix[.\-/]", "Remix"),
    (r"[/.]astro[.\-/]", "Astro"),
    (r"[/.]ember[.\-/]", "Ember.js"),
    (r"[/.]backbone[.\-/]", "Backbone.js"),

    # UI libraries
    (r"[/.]jquery[.\-]", "jQuery"),
    (r"[/.]bootstrap[.\-]", "Bootstrap"),
    (r"[/.]tailwind[.\-]", "Tailwind CSS"),
    (r"[/.]bulma[.\-]", "Bulma"),
    (r"[/.]foundation[.\-]", "Foundation"),
    (r"[/.]materialize[.\-]", "Materialize"),
    (r"[/.]alpine[.\-]", "Alpine.js"),
    (r"[/.]htmx[.\-]", "htmx"),
    (r"[/.]stimulus[.\-]", "Stimulus"),
    (r"[/.]turbo[.\-]", "Turbo"),
    (r"[/.]livewire[.\-]", "Livewire"),

    # Bundlers / runtimes
    (r"[/.]webflow[.\-]", "Webflow"),
    (r"[/.]webpack[.\-]", "Webpack"),
    (r"[/.]vite[.\-]", "Vite"),

    # Analytics / marketing
    (r"gtag/js", "Google Tag Manager"),
    (r"googletagmanager\.com", "Google Tag Manager"),
    (r"google-analytics\.com", "Google Analytics"),
    (r"analytics\.js", "Google Analytics"),
    (r"fbevents\.js", "Facebook Pixel"),
    (r"connect\.facebook\.net", "Facebook SDK"),
    (r"snap\.licdn\.com", "LinkedIn Insight"),
    (r"bat\.bing\.com", "Microsoft Clarity/Ads"),
    (r"clarity\.ms", "Microsoft Clarity"),
    (r"hotjar\.com", "Hotjar"),
    (r"plausible\.io", "Plausible Analytics"),
    (r"cdn\.segment\.com", "Segment"),
    (r"mixpanel\.com", "Mixpanel"),
    (r"amplitude\.com", "Amplitude"),
    (r"heap-?analytics", "Heap"),
    (r"fullstory\.com", "FullStory"),
    (r"sentry[.\-]io", "Sentry"),
    (r"datadoghq\.com", "Datadog"),
    (r"logrocket\.com", "LogRocket"),

    # Chat / support
    (r"intercom\.io", "Intercom"),
    (r"intercomcdn\.com", "Intercom"),
    (r"crisp\.chat", "Crisp"),
    (r"zendesk\.com", "Zendesk"),
    (r"drift\.com", "Drift"),
    (r"tawk\.to", "Tawk.to"),
    (r"livechatinc\.com", "LiveChat"),
    (r"freshdesk\.com", "Freshdesk"),

    # Payments
    (r"js\.stripe\.com", "Stripe"),
    (r"paypal\.com/sdk", "PayPal"),
    (r"square\.com", "Square"),

    # Other SaaS
    (r"recaptcha", "Google reCAPTCHA"),
    (r"hcaptcha\.com", "hCaptcha"),
    (r"turnstile", "Cloudflare Turnstile"),
    (r"cookiebot\.com", "Cookiebot"),
    (r"onetrust\.com", "OneTrust"),
    (r"cookielaw\.org", "OneTrust"),
    (r"typekit\.net", "Adobe Fonts"),
    (r"fonts\.googleapis\.com", "Google Fonts"),
    (r"use\.fontawesome\.com", "Font Awesome"),
    (r"unpkg\.com", "unpkg CDN"),
    (r"cdnjs\.cloudflare\.com", "cdnjs"),
    (r"jsdelivr\.net", "jsDelivr"),
]

# ═══════════════════════════════════════════════════════════════════
#  Inline JS global variable detection
# ═══════════════════════════════════════════════════════════════════

INLINE_JS_PATTERNS: list[tuple[str, str]] = [
    (r"__NEXT_DATA__", "Next.js"),
    (r"__NUXT__", "Nuxt.js"),
    (r"__GATSBY", "Gatsby"),
    (r"Shopify\.", "Shopify"),
    (r"Webflow\.", "Webflow"),
    (r"wp-content", "WordPress"),
    (r"wp-includes", "WordPress"),
    (r"wixBiSession", "Wix"),
    (r"squarespace\.com", "Squarespace"),
    (r"__remixContext", "Remix"),
    (r"__astro", "Astro"),
]

# ═══════════════════════════════════════════════════════════════════
#  Categorization
# ═══════════════════════════════════════════════════════════════════

_CATEGORY_MAP = {
    "Server / Hosting": {
        "nginx", "apache", "iis", "litespeed", "caddy", "openresty",
        "cloudflare", "cloudflare pages", "cloudflare workers",
        "aws", "aws cloudfront", "azure", "azure cdn", "google cloud",
        "netlify", "vercel", "heroku", "digitalocean", "fly.io", "render",
        "railway", "fastly", "akamai", "edgecast", "stackpath",
        "firebase", "supabase", "godaddy",
    },
    "Framework / CMS": {
        "react", "vue.js", "angular", "svelte", "next.js", "nuxt.js",
        "gatsby", "remix", "astro", "ember.js", "backbone.js",
        "wordpress", "joomla", "drupal", "shopify", "squarespace",
        "wix", "webflow", "ghost", "framer", "webnode", "carrd",
        "hubspot", "contentful", "prismic", "sanity", "storyblok",
        "asp.net",
    },
    "UI / CSS": {
        "jquery", "bootstrap", "tailwind css", "bulma", "foundation",
        "materialize", "alpine.js", "htmx", "stimulus", "turbo",
        "livewire", "google fonts", "adobe fonts", "font awesome",
    },
    "Analytics / Marketing": {
        "google tag manager", "google analytics", "facebook pixel",
        "facebook sdk", "linkedin insight", "microsoft clarity/ads",
        "microsoft clarity", "hotjar", "plausible analytics", "segment",
        "mixpanel", "amplitude", "heap", "fullstory",
    },
    "Developer Tools": {
        "sentry", "datadog", "logrocket", "webpack", "vite",
        "unpkg cdn", "cdnjs", "jsdelivr",
    },
    "Chat / Support": {
        "intercom", "crisp", "zendesk", "drift", "tawk.to",
        "livechat", "freshdesk",
    },
    "Payments": {
        "stripe", "paypal", "square",
    },
    "Security / Compliance": {
        "google recaptcha", "hcaptcha", "cloudflare turnstile",
        "cookiebot", "onetrust",
    },
}

# Invert for lookup
_TECH_TO_CATEGORY: dict[str, str] = {}
for _cat, _techs in _CATEGORY_MAP.items():
    for _t in _techs:
        _TECH_TO_CATEGORY[_t] = _cat


# ═══════════════════════════════════════════════════════════════════
#  Extraction helpers
# ═══════════════════════════════════════════════════════════════════

_SRC_RE = re.compile(
    r'''<(?:script|link|img)[^>]+(?:src|href)\s*=\s*["\']([^"\']+)["\']''',
    re.IGNORECASE,
)


def _extract_asset_urls(html: str) -> list[str]:
    """Pull all src/href URLs from script, link, and img tags."""
    return _SRC_RE.findall(html)


def _detect_from_assets(
    urls: list[str],
    cdn_map: list[tuple[str, str]],
    asset_patterns: list[tuple[str, str]],
) -> list[dict[str, str]]:
    """Match asset URLs against CDN domains and path patterns."""
    hits: list[dict[str, str]] = []
    seen: set[str] = set()

    for url in urls:
        url_lower = url.lower()

        for domain_pattern, tech in cdn_map:
            if domain_pattern in url_lower and tech.lower() not in seen:
                seen.add(tech.lower())
                hits.append({
                    "name": tech,
                    "source": f"CDN domain: {domain_pattern}",
                    "detail": _truncate_url(url),
                })

        for pattern, tech in asset_patterns:
            if tech.lower() not in seen and re.search(pattern, url_lower):
                seen.add(tech.lower())
                hits.append({
                    "name": tech,
                    "source": "Asset URL pattern",
                    "detail": _truncate_url(url),
                })

    return hits


def _detect_from_inline_js(
    html: str,
    js_patterns: list[tuple[str, str]],
) -> list[dict[str, str]]:
    """Detect tech from inline JS globals and known markers."""
    hits: list[dict[str, str]] = []
    seen: set[str] = set()

    for pattern, tech in js_patterns:
        if tech.lower() not in seen and re.search(pattern, html):
            seen.add(tech.lower())
            hits.append({
                "name": tech,
                "source": "Inline JS marker",
                "detail": pattern.replace("\\", ""),
            })

    return hits


def _categorize(
    techs: list[dict[str, str]],
    extra_categories: dict[str, str] | None = None,
) -> dict[str, list[dict[str, str]]]:
    """Group technologies into display categories."""
    groups: dict[str, list[dict[str, str]]] = {}
    for tech in techs:
        key = tech["name"].lower()
        cat = _TECH_TO_CATEGORY.get(key)
        if cat is None and extra_categories:
            cat = extra_categories.get(key)
        if cat is None:
            cat = "Other"
        groups.setdefault(cat, []).append(tech)
    return groups


def _truncate_url(url: str, max_len: int = 120) -> str:
    return url if len(url) <= max_len else url[:max_len] + "..."


# ═══════════════════════════════════════════════════════════════════
#  Pattern merging
# ═══════════════════════════════════════════════════════════════════

def _merge_patterns(custom_patterns: dict | None) -> tuple[
    list[tuple[str, str]],       # cdn_map
    list[tuple[str, str]],       # asset_patterns
    list[tuple[str, str]],       # js_patterns
    dict[str, str | None],       # header_techs
    dict[str, str],              # tech_paths
    dict[str, str],              # extra_categories
]:
    """Merge custom patterns into effective working copies of defaults."""
    eff_cdn = list(CDN_DOMAIN_MAP)
    eff_asset = list(ASSET_PATH_PATTERNS)
    eff_inline = list(INLINE_JS_PATTERNS)
    eff_headers = dict(HEADER_TECHS)
    eff_paths = dict(TECH_PATHS)
    extra_categories: dict[str, str] = {}

    if not custom_patterns:
        return eff_cdn, eff_asset, eff_inline, eff_headers, eff_paths, extra_categories

    _validate_custom_patterns(custom_patterns)

    for p in custom_patterns.get("cdn_domains", []):
        eff_cdn.append((p["pattern"], p["name"]))
        if "category" in p:
            extra_categories[p["name"].lower()] = p["category"]

    for p in custom_patterns.get("asset_paths", []):
        eff_asset.append((p["pattern"], p["name"]))
        if "category" in p:
            extra_categories[p["name"].lower()] = p["category"]

    for p in custom_patterns.get("inline_js", []):
        eff_inline.append((p["pattern"], p["name"]))
        if "category" in p:
            extra_categories[p["name"].lower()] = p["category"]

    for p in custom_patterns.get("headers", []):
        eff_headers[p["pattern"]] = p["name"] or None
        if "category" in p and p["name"]:
            extra_categories[p["name"].lower()] = p["category"]

    for p in custom_patterns.get("paths", []):
        eff_paths[p["pattern"]] = p["name"]
        if "category" in p:
            extra_categories[p["name"].lower()] = p["category"]

    return eff_cdn, eff_asset, eff_inline, eff_headers, eff_paths, extra_categories


# ═══════════════════════════════════════════════════════════════════
#  Main scan
# ═══════════════════════════════════════════════════════════════════

@with_retry(config=_retry)
def _fetch_page(domain: str) -> tuple[dict[str, str], str]:
    throttle(f"https://{domain}")
    resp = requests.get(
        f"https://{domain}",
        timeout=_retry.timeout_per_attempt,
        allow_redirects=True,
        headers={"User-Agent": "domain-audit/0.1"},
    )
    return dict(resp.headers), resp.text[:100000]


def scan(domain: str, custom_patterns: dict | None = None) -> ScanResult:
    start = time.time()
    technologies: list[dict[str, str]] = []
    raw_data: dict[str, Any] = {}

    # Merge custom patterns into effective lists
    eff_cdn, eff_asset, eff_inline, eff_headers, eff_paths, extra_cats = _merge_patterns(custom_patterns)

    try:
        headers, body = _fetch_page(domain)
        raw_data["response_headers"] = headers

        # 1. Response headers
        for header_name, tech_name in eff_headers.items():
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

        # 2. Meta tags
        for pattern, tag_type in META_PATTERNS.items():
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                technologies.append({
                    "name": match.group(1).strip(),
                    "source": f"Meta tag: {tag_type}",
                    "detail": match.group(1).strip(),
                })

        # 3. Known URL paths in body (classic CMS probing)
        for path, tech_name in eff_paths.items():
            if path in body:
                if not any(t["name"] == tech_name for t in technologies):
                    technologies.append({
                        "name": tech_name,
                        "source": f"URL pattern: {path}",
                        "detail": f"Found {path} reference in page",
                    })

        # 4. Asset URL analysis (scripts, stylesheets, images)
        asset_urls = _extract_asset_urls(body)
        raw_data["asset_urls_scanned"] = len(asset_urls)
        technologies.extend(_detect_from_assets(asset_urls, eff_cdn, eff_asset))

        # 5. Inline JS globals / markers
        technologies.extend(_detect_from_inline_js(body, eff_inline))

        # Deduplicate by name (keep first seen)
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

        # Group by category for display
        categories = _categorize(unique_techs, extra_cats)
        findings: list[dict[str, Any]] = []

        for category, techs in categories.items():
            names = ", ".join(t["name"] for t in techs)
            findings.append({
                "label": category,
                "value": [t["name"] for t in techs],
                "grade": "-",
                "detail": names,
                "fix": "",
            })

        if not findings:
            findings.append({
                "label": "Detected technologies",
                "value": "None detected",
                "grade": "-",
                "detail": f"No technologies detected (scanned {len(asset_urls)} asset URLs)",
                "fix": "",
            })

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
