# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in domain-audit, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@opticsponge.com** (or use [GitHub private vulnerability reporting](https://github.com/Opticsponge/domain-audit/security/advisories/new) if available).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive an acknowledgement within 48 hours. We aim to release a fix within 7 days for critical issues.

## Scope

The following are in scope:
- SSRF or internal network scanning via crafted domain input
- Command injection via domain names or scanner inputs
- XSS in Colab HTML output
- Information leakage in error messages
- Dependency vulnerabilities in direct dependencies

Out of scope:
- Scanning results accuracy (false positives/negatives in security grades)
- Rate limiting of third-party APIs (crt.sh, ip-api.com, etc.)
- Issues in the target domain being scanned
