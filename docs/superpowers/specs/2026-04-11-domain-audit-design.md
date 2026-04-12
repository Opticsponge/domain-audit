# domain-audit Design Spec

## Overview

**domain-audit** is an open-source Python tool that performs comprehensive domain health audits — DNS enumeration, subdomain discovery, SSL certificate health, HTTP security headers, WHOIS info, port scanning, email security (SPF/DKIM/DMARC), and technology detection. Results are graded pass/fail with actionable fix recommendations for sysadmins/DevOps.

Distributed as a pip-installable package with a Google Colab notebook for zero-setup browser-based testing.

**License:** MIT

---

## Architecture: Python Package + Colab Notebook

### Project Structure

```
domain-audit/
├── domain_audit/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── core.py             # Orchestrator — runs all scanners, aggregates results
│   ├── grader.py           # Pass/Warn/Fail grading logic
│   ├── retry.py            # Shared retry decorator + config
│   ├── report.py           # Output formatting (table, JSON, Colab rich HTML)
│   └── scanners/
│       ├── __init__.py
│       ├── dns_records.py   # All DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV)
│       ├── subdomains.py    # Subdomain discovery via CT logs + wordlist
│       ├── ssl_check.py     # SSL cert validity, expiration, chain, protocol versions
│       ├── headers.py       # HTTP security headers (HSTS, CSP, X-Frame, etc.)
│       ├── whois_info.py    # WHOIS lookup, domain expiry
│       ├── ports.py         # Common port scan (80, 443, 22, 8080, 8443, 21, 25, 3306, etc.)
│       ├── email_security.py # SPF, DKIM, DMARC validation
│       └── tech_detect.py   # Server, CMS, framework fingerprinting
├── notebooks/
│   └── domain_audit.ipynb   # Google Colab notebook
├── pyproject.toml
├── README.md
├── LICENSE
└── tests/
    ├── test_dns_records.py
    ├── test_ssl_check.py
    ├── test_headers.py
    ├── test_whois_info.py
    ├── test_ports.py
    ├── test_email_security.py
    ├── test_tech_detect.py
    └── test_grader.py
```

---

## Scanner Interface

Every scanner returns a standardized `ScanResult`:

```python
@dataclass
class ScanResult:
    module: str          # "ssl", "dns", "whois", etc.
    status: str          # "pass", "warn", "fail", "error"
    grade: str           # "A", "B", "C", "F", "?"
    findings: list[dict] # Individual check results
    raw_data: dict       # Full raw response for debugging
    elapsed: float       # Seconds taken
    retries: int         # How many retries were needed
```

Each scanner is a module with a `scan(domain: str) -> ScanResult` function. Scanners are independent — can be run alone or as part of a full audit.

---

## Retry Strategy

Shared retry decorator with exponential backoff + jitter:

```python
@dataclass
class RetryConfig:
    max_retries: int = 3
    base_delay: float = 1.0
    backoff_factor: float = 2.0
    retry_on: tuple = (TimeoutError, ConnectionError, socket.timeout)
    timeout_per_attempt: float = 10.0
```

Usage:
```python
@with_retry(config=RetryConfig(max_retries=3))
def scan(domain: str) -> ScanResult:
    ...
```

### Per-Scanner Defaults

| Scanner | Timeout/attempt | Max retries | Reason |
|---------|----------------|-------------|--------|
| DNS records | 5s | 3 | Fast, but DNS servers can be flaky |
| Subdomains (CT logs) | 15s | 3 | External API, can be slow |
| SSL check | 10s | 3 | TLS handshake can hang |
| Headers | 10s | 2 | Simple HTTP GET |
| WHOIS | 10s | 3 | WHOIS servers rate-limit aggressively |
| Ports | 3s per port | 1 | Slow ports are likely filtered, no point retrying |
| Email security | 5s | 3 | DNS-based lookups |
| Tech detection | 10s | 2 | HTTP-based |

If all retries fail, scanner returns `status="error"` — never crashes the full audit. The orchestrator runs scanners in parallel via `concurrent.futures`, each with independent retry state.

---

## Grading System

### Individual Check Grades

| Grade | Meaning | Example |
|-------|---------|---------|
| **A** | Excellent | SSL cert valid, >90 days to expiry |
| **B** | Good, minor concern | SSL cert valid, 30-90 days to expiry |
| **C** | Needs attention | Missing HSTS header, weak SPF record |
| **F** | Failing | Expired SSL, open database port, no DMARC |
| **?** | Could not check | Scanner errored after retries |

### Module Grade

Worst individual check grade in that module (conservative).

### Overall Grade

Weighted average across modules:

| Module | Weight | Rationale |
|--------|--------|-----------|
| SSL | 25% | Core security, most visible |
| DNS | 15% | Foundation, but less actionable |
| Email Security | 15% | SPF/DKIM/DMARC critical for phishing prevention |
| HTTP Headers | 15% | Direct security impact |
| WHOIS | 10% | Expiry matters, rest is informational |
| Ports | 10% | Exposure risk |
| Tech Detection | 5% | Informational, less actionable |
| Subdomains | 5% | Discovery, not pass/fail |

Grade mapping: A=4, B=3, C=2, F=0. Weighted sum maps back to letter grade.

---

## Scanner Details

### 1. DNS Records (`dns_records.py`)
- Query: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV
- Grading: A if all expected records present, C if missing MX/NS, F if no A/AAAA

### 2. Subdomain Discovery (`subdomains.py`)
- Source: crt.sh (Certificate Transparency logs) — free, no API key
- Returns deduplicated list of subdomains
- Grade: informational only (dash, not letter grade)

### 3. SSL/TLS Check (`ssl_check.py`)
- Certificate validity and chain verification
- Expiration date + days remaining
- Protocol versions supported (flag TLS 1.0/1.1 as bad)
- Hostname match verification
- Grading: A (valid, >90d), B (valid, 30-90d), C (valid, <30d), F (expired/invalid)

### 4. HTTP Security Headers (`headers.py`)
- Check: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- Grading: A (all present), B (most present), C (some missing), F (none present)

### 5. WHOIS (`whois_info.py`)
- Registrar, creation date, expiry date, name servers
- Grading: A (>180d to expiry), B (90-180d), C (30-90d), F (<30d or expired)

### 6. Port Scan (`ports.py`)
- Scan: 21, 22, 25, 80, 443, 3306, 3389, 5432, 8080, 8443
- Grading: A (only 80/443 open), B (+ 22/25), C (unexpected ports open), F (database/RDP ports exposed)

### 7. Email Security (`email_security.py`)
- SPF: check TXT record exists and is valid
- DKIM: check common selectors (google, default, selector1, selector2)
- DMARC: check _dmarc TXT record exists and policy strength
- Grading: A (all three present+strong), B (all present, weak policy), C (partial), F (none)

### 8. Tech Detection (`tech_detect.py`)
- Server header, X-Powered-By, meta generators, known URL patterns
- Returns list of detected technologies
- Grade: informational only (dash)

---

## Dependencies

| Purpose | Library |
|---------|---------|
| DNS | `dnspython` |
| Subdomains | `requests` (crt.sh API) |
| SSL | `ssl` (stdlib) + `cryptography` |
| HTTP | `requests` |
| WHOIS | `python-whois` |
| Ports | `socket` (stdlib) |
| Email security | `dnspython` (reuse) |
| Tech detection | `requests` (reuse) |
| Output | `rich` |
| Parallel execution | `concurrent.futures` (stdlib) |

Zero API keys required.

---

## Colab Notebook UX

```
Cell 1: Install
  !pip install git+https://github.com/<user>/domain-audit.git -q

Cell 2: Run Audit
  from domain_audit import audit
  results = audit("example.com")

Cell 3: Results (auto-rendered)
  - Color-coded HTML grade card
  - Expandable sections per module
  - Action items with copy-paste fix commands

Cell 4: Export (optional)
  results.to_json("audit.json")
  results.to_csv("audit.csv")
```

---

## CLI Interface

```bash
# Full audit
domain-audit example.com

# Specific scanners only
domain-audit example.com --only ssl,dns,headers

# JSON output
domain-audit example.com --format json

# Custom timeout
domain-audit example.com --timeout 30
```

---

## Output Formats

- **Terminal:** Rich-formatted table with color grades (default)
- **Colab:** HTML-rendered grade card with expandable sections
- **JSON:** Machine-readable for CI/CD integration
- **CSV:** For spreadsheet import

---

## Action Items

Auto-generated from any check graded below A. Each item includes:
- Severity: CRITICAL / HIGH / MEDIUM / LOW
- What's wrong (plain English)
- How to fix (specific command or config where possible)

Sorted by severity descending.
