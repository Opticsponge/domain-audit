# Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-12

### Added
- DNS record scanning (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA) with zone transfer (AXFR) detection
- Subdomain discovery via Certificate Transparency logs (crt.sh, CertSpotter) with deep probe mode
- SSL/TLS certificate validation (expiry, hostname match, protocol version)
- HTTP security headers check (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Redirect chain analysis and cookie security flag checks
- WHOIS/RDAP lookup with domain age, expiry, privacy protection, DNSSEC, and EPP status checks
- Port scanning (16 ports including database and RDP detection)
- Email security scanning (SPF with lookup chain counting, DKIM with 36 selectors, DMARC policy validation)
- Technology fingerprinting via headers and HTML patterns
- A-F grading system with weighted overall grade
- Auto-generated action items sorted by severity
- CLI with `--only`, `--format` (table/json/csv), `--output`, and `--deep` flags
- Python API with `audit()`, `to_dict()`, `to_json()`, `to_csv()`
- Google Colab support with rich HTML rendering
- Retry with exponential backoff and jitter on transient failures
- Input validation: domain name regex, private/reserved IP rejection (SSRF protection)
- Error message sanitization (strips file paths and internal IPs)
- RDAP URL-encoding to prevent path traversal
- XSS-safe HTML escaping in Colab renderer

[0.1.0]: https://github.com/Opticsponge/domain-audit/releases/tag/v0.1.0
