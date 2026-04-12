<p align="center">
  <h1 align="center">domain-audit</h1>
  <p align="center">
    <strong>Comprehensive domain health auditing tool</strong>
  </p>
  <p align="center">
    DNS &bull; SSL/TLS &bull; Subdomains &bull; HTTP Headers &bull; WHOIS &bull; Ports &bull; Email Security &bull; Tech Detection
  </p>
  <p align="center">
    <a href="https://colab.research.google.com/github/Opticsponge/domain-audit/blob/main/notebooks/domain_audit.ipynb"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open In Colab"></a>
    <a href="https://pypi.org/project/domain-audit/"><img src="https://img.shields.io/pypi/v/domain-audit?color=blue" alt="PyPI"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"></a>
    <a href="https://github.com/Opticsponge/domain-audit/issues"><img src="https://img.shields.io/github/issues/Opticsponge/domain-audit" alt="GitHub Issues"></a>
    <a href="https://github.com/Opticsponge/domain-audit/stargazers"><img src="https://img.shields.io/github/stars/Opticsponge/domain-audit" alt="GitHub Stars"></a>
    <a href="https://github.com/Opticsponge/domain-audit/network/members"><img src="https://img.shields.io/github/forks/Opticsponge/domain-audit" alt="GitHub Forks"></a>
  </p>
</p>

---

Scan any domain and get an instant health report with **A-F grades** and **actionable fix recommendations**. Built for sysadmins and DevOps engineers. No API keys required.

```
╔══════════════════════════════════════════════════════╗
║         DOMAIN AUDIT: example.com                    ║
║         Overall Grade: B                             ║
╠══════════════════════════════════════════════════════╣
║ SSL/TLS           │  A  │ Valid, 142 days left       ║
║ DNS Records       │  A  │ All records found          ║
║ HTTP Headers      │  C  │ Missing CSP, HSTS          ║
║ Email Security    │  F  │ No DMARC record            ║
║ Open Ports        │  A  │ Only 80, 443 open          ║
╠══════════════════════════════════════════════════════╣
║ ACTION ITEMS:                                        ║
║ 1. [CRITICAL] Add DMARC record                      ║
║ 2. [HIGH] Add Content-Security-Policy header         ║
║ 3. [HIGH] Enable HSTS                               ║
╚══════════════════════════════════════════════════════╝
```

## Quick Start

### Try in Google Colab (zero install)

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Opticsponge/domain-audit/blob/main/notebooks/domain_audit.ipynb)

Click the badge, enter a domain, run. That's it.

### Install locally

```bash
pip install domain-audit
```

Or install from source (latest development version):

```bash
pip install git+https://github.com/Opticsponge/domain-audit.git
```

### CLI Usage

```bash
# Full audit
domain-audit example.com

# Specific scanners only
domain-audit example.com --only ssl,dns,headers

# JSON output (great for CI/CD and AI agents)
domain-audit example.com --format json

# CSV export
domain-audit example.com --format csv -o results.csv

# Custom tech detection patterns
domain-audit example.com --tech-patterns my_patterns.json
```

### Python API

```python
from domain_audit import audit

results = audit("example.com")

# Structured dict (AI-friendly)
data = results.to_dict()

# Export
results.to_json("audit.json")
results.to_csv("audit.csv")
```

## What It Checks

| Module | What It Scans | Grade |
|--------|--------------|-------|
| **SSL/TLS** | Certificate validity, expiration, hostname match, protocol version (flags TLS 1.0/1.1) | A-F |
| **DNS Records** | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA + zone transfer (AXFR) test | A-F |
| **Subdomains** | Discovery via CT logs + per-subdomain DNS, SSL, HTTP probes with data tables | Informational |
| **HTTP Headers** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy + redirect chain analysis + cookie security flags | A-F |
| **WHOIS** | Registrar info, domain creation & expiration dates, name servers | A-F |
| **Email Security** | SPF (parsed tags + chain lookup limit), DKIM (36 selectors), DMARC (parsed tags + policy tests) — MXToolbox-style tables | A-F |
| **Open Ports** | 16 ports across main domain + all discovered subdomains: FTP, SSH, SMTP, HTTP, HTTPS, MSSQL, MySQL, RDP, PostgreSQL, Elasticsearch (9200/9300), MongoDB (27017-27019), 8080, 8443 | A-F |
| **Tech Stack** | 5-source detection: response headers, meta tags, URL paths, asset/CDN URL fingerprinting, inline JS markers — ~100 built-in technologies across 8 categories + custom patterns | Informational |

## Grading System

| Grade | Meaning | Example |
|-------|---------|---------|
| **A** | Excellent | SSL cert valid, >90 days to expiry |
| **B** | Good, minor concern | SSL cert valid, 30-90 days to expiry |
| **C** | Needs attention | Missing HSTS header, weak SPF record |
| **F** | Failing | Expired SSL, open database port, no DMARC |
| **?** | Could not check | Scanner errored after retries |

**Overall grade** = weighted average across scored modules (SSL 25%, DNS 15%, Email 15%, Headers 15%, WHOIS 10%, Ports 10%). Tech and Subdomains are informational.

**Action items** are auto-generated for any check below grade A, sorted by severity:
`CRITICAL > HIGH > MEDIUM > LOW`

## Features

- **Parallel scanning** — subdomain discovery runs first, then all remaining modules run concurrently via thread pool
- **Retry with backoff** — exponential backoff + jitter on transient network failures
- **Per-scanner timeouts** — tuned defaults (3s-15s) so one slow scanner won't block the rest
- **Per-subdomain probing** — discovered subdomains get DNS, SSL, HTTP scans with data-type-specific tables
- **MXToolbox-style reports** — parsed record tables (Tag/Value/Name/Description) + validation test rows with pass/fail checkmarks
- **Structured output** — JSON and CSV export for CI/CD pipelines and AI agents
- **Colab-native** — rich color-coded HTML with summary table, expand/collapse, and detailed drill-down
- **XSS-safe** — all user data HTML-escaped in Colab renderer
- **Zero API keys** — everything works out of the box, no signup required
- **AI-friendly** — `results.to_dict()` returns clean structured data any LLM can parse

## Available Scanners

```
dns         DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA) + zone transfer test
subdomains  CT log discovery + per-subdomain DNS/SSL/HTTP probes with data tables
ssl         SSL/TLS certificate health, expiration, hostname match, protocol check
headers     Security headers + redirect chain analysis + cookie security flags
whois       WHOIS registration, domain expiry, name servers
ports       16-port scan across main domain + subdomains (HTTP, HTTPS, SSH, SMTP, MSSQL, MySQL, RDP, PostgreSQL, Elasticsearch, MongoDB)
email       SPF/DKIM/DMARC with parsed record tables, validation tests, SPF lookup chain counting
tech        5-source fingerprinting: headers, meta tags, URL paths, CDN/asset URLs, inline JS markers
```

Run specific ones with `--only`:
```bash
domain-audit example.com --only ssl,email,headers
```

## Tech Stack Detection

The tech scanner uses 5 detection sources to identify ~100 technologies:

| Source | How It Works | Example |
|--------|-------------|---------|
| **Response Headers** | Checks `Server`, `X-Powered-By`, `X-Generator`, etc. | nginx, ASP.NET, Shopify |
| **Meta Tags** | Parses `<meta name="generator">` | WordPress 6.4 |
| **URL Paths** | Finds CMS paths in page HTML (`/wp-admin/`, `/administrator/`) | WordPress, Joomla, Drupal |
| **Asset URLs** | Fingerprints `<script src>` / `<link href>` by CDN domain and filename | Webflow from CDN URL, React from bundle name |
| **Inline JS** | Detects framework globals (`__NEXT_DATA__`, `Shopify.`, `wixBiSession`) | Next.js, Shopify, Wix |

Results are grouped into 8 categories: Server/Hosting, Framework/CMS, UI/CSS, Analytics/Marketing, Developer Tools, Chat/Support, Payments, Security/Compliance.

### Custom Tech Patterns

Add your own detection patterns via Python API, CLI, or MCP:

**Python API:**

```python
from domain_audit import audit

result = audit("example.com", tech_patterns={
    "cdn_domains": [
        {"pattern": "my-cdn.corp.com", "name": "CorpCDN", "category": "Server / Hosting"},
    ],
    "asset_paths": [
        {"pattern": r"my-framework[.\-]", "name": "MyFramework", "category": "Framework / CMS"},
    ],
    "inline_js": [
        {"pattern": "__MY_APP__", "name": "MyApp"},
    ],
    "headers": [
        {"pattern": "X-My-Platform", "name": "", "category": "Server / Hosting"},
    ],
    "paths": [
        {"pattern": "/my-admin/", "name": "MyPlatform"},
    ],
})
```

**CLI with JSON file:**

```bash
domain-audit example.com --tech-patterns patterns.json
```

```json
{
  "cdn_domains": [
    {"pattern": "internal-cdn.corp.com", "name": "Internal CDN", "category": "Server / Hosting"}
  ],
  "asset_paths": [
    {"pattern": "my-framework[.\\-]", "name": "MyFramework", "category": "Framework / CMS"}
  ]
}
```

**Pattern types:**

| Key | Match Method | Use For |
|-----|-------------|---------|
| `cdn_domains` | Substring match on asset URLs | CDN domains, hosting platforms |
| `asset_paths` | Regex match on `<script>`/`<link>` URLs | JS libraries, framework bundles |
| `inline_js` | Regex match on page HTML | JS globals, framework markers |
| `headers` | Header name lookup (empty `name` → use header value) | Custom response headers |
| `paths` | Substring match in page HTML | CMS admin paths, known routes |

Each pattern: `{"pattern": "...", "name": "TechName", "category": "Optional Category"}`. Category defaults to "Other" if omitted. Patterns are additive — they extend the built-in set, never replace it.

## Output Formats

| Format | Use Case | Flag |
|--------|----------|------|
| **Table** | Terminal / human reading (default) | `--format table` |
| **HTML** | Auto-detected in Google Colab | (automatic) |
| **JSON** | CI/CD, APIs, AI agents | `--format json` |
| **CSV** | Spreadsheets, data analysis | `--format csv` |

## Development

```bash
git clone https://github.com/Opticsponge/domain-audit.git
cd domain-audit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

### Project Structure

```
domain_audit/
├── __init__.py          # Public API: audit(), AuditResult, ScanResult
├── cli.py               # CLI entry point
├── core.py              # Orchestrator — parallel scanner execution
├── grader.py            # Grading logic + action item generation
├── retry.py             # Retry decorator with exponential backoff
├── report.py            # Terminal (Rich) and Colab (HTML) renderers
└── scanners/
    ├── dns_records.py   # DNS enumeration
    ├── subdomains.py    # CT log subdomain discovery
    ├── ssl_check.py     # SSL/TLS certificate checks
    ├── headers.py       # HTTP security headers
    ├── whois_info.py    # WHOIS lookup
    ├── ports.py         # Port scanning
    ├── email_security.py # SPF/DKIM/DMARC
    └── tech_detect.py   # Technology fingerprinting
```

## Contributing

Contributions welcome! Each scanner is an independent module — easy to add new ones or improve existing checks.

### Getting Started

```bash
# 1. Fork on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/domain-audit.git
cd domain-audit

# 2. Set up development environment
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 3. Run tests
pytest tests/ -v

# 4. Create a feature branch
git checkout -b feature/new-scanner
```

### Using Your Fork in Google Colab

If you want to run your own modified version in Colab instead of the published package:

```python
# Install from YOUR fork (replace YOUR_USERNAME)
!pip install git+https://github.com/YOUR_USERNAME/domain-audit.git -q

# Or install a specific branch
!pip install git+https://github.com/YOUR_USERNAME/domain-audit.git@feature/my-branch -q

# Or clone and install in editable mode (for live editing in Colab)
!git clone https://github.com/YOUR_USERNAME/domain-audit.git /content/domain-audit
!pip install -e /content/domain-audit -q
```

### Keeping Your Fork in Sync

```bash
# Add upstream remote (one-time)
git remote add upstream https://github.com/Opticsponge/domain-audit.git

# Fetch and merge upstream changes
git fetch upstream
git merge upstream/main

# Push updated main to your fork
git push origin main
```

### Submitting Changes

1. Push your feature branch to your fork
2. Open a PR against `Opticsponge/domain-audit:main`
3. Include tests for new scanners or changed behavior

### Releasing a New Version (maintainers only)

Releases are automated via GitHub Actions using [Trusted Publishers](https://docs.pypi.org/trusted-publishers/) (no API tokens needed).

**One-time setup:**

1. Create accounts on [PyPI](https://pypi.org) and [TestPyPI](https://test.pypi.org)
2. On each, go to "Publishing" and add a Trusted Publisher:
   - Owner: `Opticsponge`
   - Repository: `domain-audit`
   - Workflow: `publish.yml`
   - Environment: `pypi` (or `testpypi` for TestPyPI)
3. In your GitHub repo, create two environments under Settings > Environments:
   - `testpypi`
   - `pypi` (optionally add required reviewers for extra safety)

**To release:**

1. Bump version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit, push, and create a GitHub Release with tag `v0.X.0`
4. The publish workflow automatically: builds, uploads to TestPyPI, then uploads to PyPI

**First-time manual upload (if not using Trusted Publishers yet):**

```bash
pip install build twine
python -m build

# Test on TestPyPI first
python -m twine upload --repository testpypi dist/*

# Verify: pip install -i https://test.pypi.org/simple/ domain-audit

# Then upload to real PyPI
python -m twine upload dist/*
```

## License

[MIT](LICENSE)

---

<p align="center">
  Made with Python &bull; <a href="https://github.com/Opticsponge/domain-audit">GitHub</a> &bull; <a href="https://colab.research.google.com/github/Opticsponge/domain-audit/blob/main/notebooks/domain_audit.ipynb">Try in Colab</a>
</p>
