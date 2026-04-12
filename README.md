# domain-audit

Comprehensive domain health auditing tool. Scans DNS records, subdomains, SSL/TLS certificates, HTTP security headers, WHOIS info, open ports, email security (SPF/DKIM/DMARC), and technology stack. Results graded A-F with actionable fix recommendations.

Built for sysadmins and DevOps engineers. No API keys required.

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Opticsponge/domain-audit/blob/main/notebooks/domain_audit.ipynb)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Quick Start

### Try in Google Colab (no install)

Click the "Open in Colab" badge above, enter a domain, and run.

### Install locally

```bash
pip install git+https://github.com/Opticsponge/domain-audit.git
```

### Run

```bash
# Full audit
domain-audit example.com

# Specific scanners only
domain-audit example.com --only ssl,dns,headers

# JSON output (great for CI/CD and AI consumption)
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

| Module | Checks | Graded |
|--------|--------|--------|
| **SSL/TLS** | Certificate validity, expiration, hostname match, protocol version | A-F |
| **DNS Records** | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV | A-F |
| **Subdomains** | Discovery via Certificate Transparency logs | Info |
| **HTTP Headers** | HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy | A-F |
| **WHOIS** | Registrar, domain expiration date | A-F |
| **Email Security** | SPF, DKIM, DMARC presence and policy strength | A-F |
| **Open Ports** | 21, 22, 25, 80, 443, 3306, 3389, 5432, 8080, 8443 | A-F |
| **Tech Stack** | Server, CMS, framework fingerprinting | Info |

## Grading

- **A** — Excellent, no issues
- **B** — Good, minor concerns
- **C** — Needs attention
- **F** — Failing, action required
- **?** — Could not check (scanner error)

Overall grade is a weighted average across modules. Action items are auto-generated for any grade below A, sorted by severity (CRITICAL > HIGH > MEDIUM > LOW).

## Features

- **Parallel scanning** — all 8 modules run concurrently
- **Retry with backoff** — exponential backoff + jitter on transient failures
- **Structured output** — JSON/CSV export for automation and AI agents
- **Colab-native** — rich HTML output when running in Google Colab
- **Zero API keys** — everything works out of the box

## Development

```bash
git clone https://github.com/Opticsponge/domain-audit.git
cd domain-audit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
