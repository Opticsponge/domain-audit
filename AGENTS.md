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
