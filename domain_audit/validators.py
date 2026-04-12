"""Input validation and security helpers for domain-audit."""

from __future__ import annotations

import ipaddress
import re

# Valid domain: at least two labels, each label is alphanumeric + hyphens,
# TLD is alphabetic (no all-numeric TLDs exist).
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"  # first label
    r"(\.[A-Za-z0-9-]{1,63})*"  # middle labels
    r"\.[A-Za-z]{2,63}$"  # TLD
)


class DomainValidationError(ValueError):
    """Raised when a domain name fails validation."""


class PrivateIPError(ValueError):
    """Raised when a resolved IP is in a private/reserved range."""


def validate_domain(domain: str) -> str:
    """Validate and normalise a domain name.

    Returns the cleaned domain or raises DomainValidationError.
    """
    domain = domain.strip().lower()

    if not domain:
        raise DomainValidationError("Domain name cannot be empty")

    if len(domain) > 253:
        raise DomainValidationError("Domain name exceeds 253 characters")

    if not _DOMAIN_RE.match(domain):
        raise DomainValidationError(
            f"Invalid domain name: {domain!r}. Must be a fully-qualified domain (e.g. example.com)"
        )

    return domain


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is a private, loopback, link-local,
    or otherwise non-globally-routable address."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False  # Not a valid IP at all — let caller decide

    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_resolved_ip(ip_str: str, domain: str = "") -> None:
    """Raise PrivateIPError if *ip_str* resolves to a non-routable address."""
    if is_private_ip(ip_str):
        ctx = f" (resolved from {domain})" if domain else ""
        raise PrivateIPError(
            f"Refusing to scan private/reserved IP {ip_str}{ctx}. Only publicly-routable addresses are allowed."
        )


def safe_error(exc: Exception) -> str:
    """Return a sanitised error string safe for user-facing output.

    Strips file paths, internal IPs, and tracebacks.
    """
    msg = str(exc)
    # Strip file paths (Unix and Windows)
    msg = re.sub(r"(/[^\s:]+\.py\b)", "<path>", msg)
    msg = re.sub(r"([A-Z]:\\[^\s:]+\.py\b)", "<path>", msg)
    # Strip private IPs from error text
    msg = re.sub(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
        "<internal-ip>",
        msg,
    )
    return msg
