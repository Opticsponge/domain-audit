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
| **DNS Records** | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV | A-F |
| **Subdomains** | Discovery via Certificate Transparency logs (crt.sh) | Informational |
| **HTTP Headers** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy | A-F |
| **WHOIS** | Registrar info, domain creation & expiration dates, name servers | A-F |
| **Email Security** | SPF record & policy, DKIM (6 common selectors), DMARC record & enforcement level | A-F |
| **Open Ports** | 21 (FTP), 22 (SSH), 25 (SMTP), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 8080, 8443 | A-F |
| **Tech Stack** | Web server, CMS, frameworks via headers, meta tags, and URL patterns | Informational |

## Grading System

| Grade | Meaning | Example |
|-------|---------|---------|
| **A** | Excellent | SSL cert valid, >90 days to expiry |
| **B** | Good, minor concern | SSL cert valid, 30-90 days to expiry |
| **C** | Needs attention | Missing HSTS header, weak SPF record |
| **F** | Failing | Expired SSL, open database port, no DMARC |
| **?** | Could not check | Scanner errored after retries |

**Overall grade** = weighted average across modules (SSL 25%, DNS 15%, Email 15%, Headers 15%, WHOIS 10%, Ports 10%, Tech 5%, Subdomains 5%).

**Action items** are auto-generated for any check below grade A, sorted by severity:
`CRITICAL > HIGH > MEDIUM > LOW`

## Features

- **Parallel scanning** — all 8 modules run concurrently via thread pool
- **Retry with backoff** — exponential backoff + jitter on transient network failures
- **Per-scanner timeouts** — tuned defaults (3s-15s) so one slow scanner won't block the rest
- **Structured output** — JSON and CSV export for CI/CD pipelines and AI agents
- **Colab-native** — rich color-coded HTML cards with expandable detail sections in Google Colab
- **Zero API keys** — everything works out of the box, no signup required
- **AI-friendly** — `results.to_dict()` returns clean structured data any LLM can parse

## Available Scanners

```
dns         DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV)
subdomains  Subdomain discovery via Certificate Transparency logs
ssl         SSL/TLS certificate health, expiration, protocol check
headers     HTTP security headers audit
whois       WHOIS domain registration and expiry info
ports       Common port scan (10 ports)
email       Email security: SPF, DKIM, DMARC validation
tech        Technology stack detection
```

Run specific ones with `--only`:
```bash
domain-audit example.com --only ssl,email,headers
```

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

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-scanner`)
3. Add tests for your changes
4. Submit a PR

## License

[MIT](LICENSE)

---

<p align="center">
  Made with Python &bull; <a href="https://github.com/Opticsponge/domain-audit">GitHub</a> &bull; <a href="https://colab.research.google.com/github/Opticsponge/domain-audit/blob/main/notebooks/domain_audit.ipynb">Try in Colab</a>
</p>
