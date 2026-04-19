# AGENTS.md

## Identity

- **Name:** domain-audit
- **Version:** 0.1.1
- **Purpose:** Structured domain intelligence — DNS, SSL/TLS, WHOIS, email security, HTTP headers, open ports, subdomains, tech stack.
- **Read-only:** Yes. Queries public data. Does not modify DNS, certificates, or any remote state.
- **API keys required:** None.

## Capabilities

| Scanner    | Returns                                                       | Graded |
|-----------|---------------------------------------------------------------|--------|
| dns       | A, AAAA, MX, NS, TXT, CAA, SOA, SRV, CNAME + zone transfer  | Yes    |
| ssl       | Certificate validity, expiration, hostname match, TLS version | Yes    |
| headers   | Security headers, redirect chain, cookie flags                | Yes    |
| whois     | Registrar, expiry, name servers, DNSSEC                       | Yes    |
| email     | SPF, DKIM (36 selectors), DMARC                              | Yes    |
| ports     | 16 ports across domain + subdomains                           | Yes    |
| subdomains| CT log discovery + per-subdomain probes                       | No     |
| tech      | Technology fingerprinting from 6 sources (~150 technologies)  | No     |

## Constraints

- Network-dependent. Per-scanner timeouts (3–15s) with retry and exponential backoff.
- Port scanning may be blocked by firewalls or rate-limited by target infrastructure.
- WHOIS data varies by registrar and TLD. Some fields may be redacted.
- Rate-limited internally: 10 req/s global, 2 req/s per host.

## Output Schema

### ScanResult

| Field    | Type         | Description                                |
|----------|--------------|--------------------------------------------|
| module   | string       | Scanner name (e.g., "ssl", "dns")          |
| status   | string       | "pass", "warn", "fail", "error"            |
| grade    | string       | "A", "B", "C", "F", "?", "-"              |
| findings | list[object] | Individual checks with grades and fix text |
| raw_data | object       | Scanner-specific structured data           |
| elapsed  | float        | Seconds taken                              |
| retries  | int          | Retry count                                |

### Finding

| Field  | Type   | Description                          |
|--------|--------|--------------------------------------|
| label  | string | What was checked                     |
| grade  | string | Grade for this finding               |
| detail | string | Human-readable result                |
| fix    | string | Remediation text (empty if passing)  |

### Full Audit Response

| Field           | Type         | Description                                          |
|-----------------|--------------|------------------------------------------------------|
| domain          | string       | Target domain                                        |
| overall_grade   | string       | Weighted average: A, B, C, F, ?                      |
| elapsed_seconds | float        | Total wall time                                      |
| modules         | object       | Map of scanner name → ScanResult                     |
| action_items    | list[object] | Sorted by severity: CRITICAL > HIGH > MEDIUM > LOW   |

### Action Item

| Field    | Type   | Description                  |
|----------|--------|------------------------------|
| severity | string | CRITICAL, HIGH, MEDIUM, LOW  |
| module   | string | Which scanner produced it    |
| issue    | string | What's wrong                 |
| detail   | string | Context                      |
| fix      | string | How to fix                   |

### Grade Weights

SSL 25%, DNS 15%, Email 15%, Headers 15%, WHOIS 10%, Ports 10%. Subdomains and Tech are informational.

### Example

```json
{
  "domain": "example.com",
  "overall_grade": "B",
  "elapsed_seconds": 5.4,
  "modules": {
    "ssl": {
      "module": "ssl",
      "status": "pass",
      "grade": "A",
      "findings": [
        {"label": "Certificate", "grade": "A", "detail": "Valid, expires in 364 days", "fix": ""}
      ],
      "raw_data": {"issuer": "Let's Encrypt", "not_after": "2027-04-11"},
      "elapsed": 1.2,
      "retries": 0
    }
  },
  "action_items": [
    {"severity": "CRITICAL", "module": "email", "issue": "No DMARC record", "detail": "...", "fix": "Add a DMARC TXT record"}
  ]
}
```
