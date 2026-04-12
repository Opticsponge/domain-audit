"""MCP server for domain-audit — exposes scanners as agent-callable tools."""

from __future__ import annotations

import dataclasses

from mcp.server.fastmcp import FastMCP

from domain_audit.core import audit
from domain_audit.scanners import SCANNERS
from domain_audit.validators import DomainValidationError, validate_domain

mcp = FastMCP("domain-audit")

_SCANNER_DESCRIPTIONS = {
    "dns": "DNS records — A, AAAA, MX, NS, TXT, CAA, SOA, SRV, CNAME, plus zone transfer test",
    "subdomains": "Subdomain discovery via Certificate Transparency logs (crt.sh, CertSpotter)",
    "ssl": "SSL/TLS certificate validity, expiration, hostname match, and TLS version",
    "headers": "HTTP security headers — HSTS, CSP, X-Frame-Options, redirects, cookies",
    "whois": "WHOIS/RDAP — registrar, expiry date, DNSSEC, privacy protection, EPP status",
    "ports": "Open port detection across 16 common ports (HTTP, SSH, SMTP, DB, RDP, etc.)",
    "email": "Email security — SPF, DKIM (36 selectors), DMARC validation and policy",
    "tech": "Technology fingerprinting — web server, CMS, frameworks, CDN, analytics",
}


@mcp.tool()
def list_scanners() -> dict:
    """List available domain audit scanners with descriptions."""
    return {"scanners": [{"name": name, "description": _SCANNER_DESCRIPTIONS.get(name, name)} for name in SCANNERS]}


def _run_scanner(name: str, domain: str, **kwargs) -> dict:
    """Validate domain, run a single scanner, return result as dict."""
    try:
        domain = validate_domain(domain)
    except DomainValidationError as exc:
        return {"error": str(exc), "module": name}
    try:
        result = SCANNERS[name](domain, **kwargs)
        return dataclasses.asdict(result)
    except Exception as exc:
        return {"error": str(exc), "module": name}


@mcp.tool()
def scan_dns(domain: str) -> dict:
    """Scan DNS records — A, AAAA, MX, NS, TXT, CAA, SOA, SRV, CNAME, plus zone transfer test."""
    return _run_scanner("dns", domain)


@mcp.tool()
def scan_subdomains(domain: str, deep: bool = False) -> dict:
    """Discover subdomains via Certificate Transparency logs (crt.sh, CertSpotter)."""
    return _run_scanner("subdomains", domain, deep=deep)


@mcp.tool()
def scan_ssl(domain: str) -> dict:
    """Check SSL/TLS certificate validity, expiration, hostname match, and TLS version."""
    return _run_scanner("ssl", domain)


@mcp.tool()
def scan_headers(domain: str) -> dict:
    """Check HTTP security headers — HSTS, CSP, X-Frame-Options, redirects, cookies."""
    return _run_scanner("headers", domain)


@mcp.tool()
def scan_whois(domain: str) -> dict:
    """Look up WHOIS/RDAP — registrar, expiry date, DNSSEC, privacy protection, EPP status."""
    return _run_scanner("whois", domain)


@mcp.tool()
def scan_ports(domain: str, subdomains: list[str] | None = None) -> dict:
    """Detect open ports across 16 common ports (HTTP, SSH, SMTP, DB, RDP, etc.).

    Pass discovered subdomains to scan them too (otherwise only the main domain is scanned).
    """
    kwargs = {}
    if subdomains:
        kwargs["subdomains"] = subdomains
    return _run_scanner("ports", domain, **kwargs)


@mcp.tool()
def scan_email(domain: str) -> dict:
    """Validate email security — SPF, DKIM (36 selectors), DMARC policy."""
    return _run_scanner("email", domain)


@mcp.tool()
def scan_tech(domain: str, custom_patterns: dict | None = None) -> dict:
    """Fingerprint technology stack — web server, CMS, frameworks, CDN, analytics.

    Pass custom_patterns to extend built-in detection with your own patterns.
    Keys: cdn_domains, asset_paths, inline_js, headers, paths, dns_txt, dns_cname.
    Each entry: {"pattern": "...", "name": "TechName", "category": "Optional Category"}.
    """
    kwargs = {}
    if custom_patterns:
        kwargs["custom_patterns"] = custom_patterns
    return _run_scanner("tech", domain, **kwargs)


@mcp.tool()
def audit_domain(
    domain: str,
    scanners: list[str] | None = None,
    deep: bool = False,
    tech_patterns: dict | None = None,
) -> dict:
    """Run comprehensive domain health audit across all or selected scanners.

    Returns overall grade, per-module results, and prioritised action items.
    Pass scanner names (dns, ssl, headers, whois, ports, email, tech, subdomains)
    to run specific modules only.  Pass tech_patterns to extend tech detection.
    """
    try:
        result = audit(domain, only=scanners, show=False, deep_subdomains=deep, tech_patterns=tech_patterns)
        return result.to_dict()
    except Exception as exc:
        return {"error": str(exc), "domain": domain}


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
