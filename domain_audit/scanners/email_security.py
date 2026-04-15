from __future__ import annotations

import re
import time
from typing import Any

import dns.exception
import dns.resolver

from domain_audit.grader import ScanResult, worst_grade
from domain_audit.retry import RetryConfig, with_retry

DKIM_SELECTORS = [
    "google",
    "default",
    "selector1",
    "selector2",
    "dkim",
    "mail",
    # Common providers
    "s1",
    "s2",
    "k1",
    "k2",
    "k3",
    "mandrill",
    "mte1",
    "mte2",  # Mailchimp/Mandrill
    "amazonses",
    "ug7nbtf4gccmlpwj322ax3p6ow6fovbn",  # Amazon SES
    "sendgrid",
    "smtpapi",
    "s1._domainkey",
    "em",  # SendGrid
    "pm",
    "protonmail",
    "protonmail2",
    "protonmail3",  # Protonmail
    "fm1",
    "fm2",
    "fm3",  # Fastmail
    "mailjet",  # Mailjet
    "smtp",
    "mailo",  # Generic
    "postmark",  # Postmark
    "turbo-smtp",  # Turbo-SMTP
    "hs1",
    "hs2",  # HubSpot
    "zendesk1",
    "zendesk2",  # Zendesk
]

# DMARC tag descriptions
DMARC_TAG_INFO = {
    "v": ("Version", "Identifies the retrieved as a DMARC record. Must be the first tag."),
    "p": (
        "Policy",
        "Policy to apply to email that fails the DMARC test. Valid values: 'none', 'quarantine', or 'reject'.",
    ),
    "sp": ("Subdomain Policy", "Policy for subdomains. Defaults to the 'p' value if not set."),
    "rua": ("Receivers", "Addresses to which aggregate feedback is to be sent. Comma separated list of DMARC URIs."),
    "ruf": ("Forensic Receivers", "Addresses to which message-specific failure information is to be reported."),
    "fo": (
        "Forensic Reporting",
        "Options for generation of failure reports. Valid values: any combination of '01ds' separated by ':'.",
    ),
    "pct": (
        "Percentage",
        "Percentage of messages the DMARC policy is applied to. Valid value: integer between 0 and 100.",
    ),
    "adkim": ("DKIM Alignment", "Alignment mode for DKIM. 'r' = relaxed (default), 's' = strict."),
    "aspf": ("SPF Alignment", "Alignment mode for SPF. 'r' = relaxed (default), 's' = strict."),
    "rf": ("Report Format", "Format for message-specific failure reports. Default: 'afrf'."),
    "ri": ("Report Interval", "Interval (seconds) between aggregate reports. Default: 86400 (24 hours)."),
}

# SPF mechanism descriptions
SPF_MECHANISM_INFO = {
    "v": ("Version", "SPF version identifier. Must be 'spf1'."),
    "include": ("Include", "Authorizes the designated domain's SPF senders."),
    "a": ("A Record", "Authorizes the domain's A record IP addresses to send mail."),
    "mx": ("MX Record", "Authorizes the domain's MX hosts to send mail."),
    "ip4": ("IPv4 Address", "Authorizes the specified IPv4 address or CIDR range to send mail."),
    "ip6": ("IPv6 Address", "Authorizes the specified IPv6 address or CIDR range to send mail."),
    "all": ("All", "Matches all senders. Qualifier determines action: '-' fail, '~' softfail, '+' pass, '?' neutral."),
    "redirect": ("Redirect", "Redirects SPF check to another domain's SPF record."),
    "exists": ("Exists", "Matches if the specified domain resolves to any address."),
    "ptr": ("PTR", "Matches if the sender's PTR record resolves within the given domain. Deprecated."),
}

_retry = RetryConfig(max_retries=3, timeout_per_attempt=5.0)


class _DnsLookupFailed(Exception):
    """Raised when DNS lookup fails due to network/timeout, not missing records."""

    pass


@with_retry(config=_retry)
def _resolve_txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=_retry.timeout_per_attempt)
        # Join multi-part TXT records and strip quotes
        results = []
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings)
            results.append(txt)
        return results
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        # Legitimate: record doesn't exist
        return []
    except dns.exception.DNSException as exc:
        # Network/timeout failure — caller should NOT treat as "no record"
        raise _DnsLookupFailed(f"DNS lookup failed for {name}: {exc}") from exc


# ═══════════════════════════════════════════════════════════════════
#  SPF
# ═══════════════════════════════════════════════════════════════════


def _strip_qualifier(part: str) -> tuple[str, str]:
    """Strip SPF qualifier prefix (+, -, ~, ?) and return (qualifier, mechanism)."""
    if part and part[0] in "+-~?":
        return part[0], part[1:]
    return "+", part  # default qualifier is pass


def _parse_spf(record: str) -> list[dict[str, str]]:
    """Parse SPF record into tag/value table rows."""
    rows = []
    parts = record.split()
    for part in parts:
        if part.startswith("v="):
            rows.append({"tag": "v", "value": part[2:], "name": "Version", "description": SPF_MECHANISM_INFO["v"][1]})
            continue

        qualifier, mech = _strip_qualifier(part)
        qual_label = {"+": "Pass", "-": "Fail", "~": "SoftFail", "?": "Neutral"}.get(qualifier, "")

        if mech.startswith("include:"):
            domain = mech[8:]
            rows.append(
                {
                    "tag": "include",
                    "value": domain,
                    "name": f"Include ({qual_label})",
                    "description": f"Authorizes senders from {domain}'s SPF policy.",
                }
            )
        elif mech.startswith("redirect="):
            domain = mech[9:]
            rows.append(
                {
                    "tag": "redirect",
                    "value": domain,
                    "name": "Redirect",
                    "description": f"Redirects SPF evaluation to {domain}.",
                }
            )
        elif mech.startswith("ip4:"):
            rows.append(
                {
                    "tag": "ip4",
                    "value": mech[4:],
                    "name": f"IPv4 ({qual_label})",
                    "description": f"Authorizes {mech[4:]} to send mail.",
                }
            )
        elif mech.startswith("ip6:"):
            rows.append(
                {
                    "tag": "ip6",
                    "value": mech[4:],
                    "name": f"IPv6 ({qual_label})",
                    "description": f"Authorizes {mech[4:]} to send mail.",
                }
            )
        elif mech == "a" or mech.startswith("a:") or mech.startswith("a/"):
            rows.append(
                {
                    "tag": "a",
                    "value": part,
                    "name": f"A Record ({qual_label})",
                    "description": SPF_MECHANISM_INFO["a"][1],
                }
            )
        elif mech == "mx" or mech.startswith("mx:") or mech.startswith("mx/"):
            rows.append(
                {
                    "tag": "mx",
                    "value": part,
                    "name": f"MX Record ({qual_label})",
                    "description": SPF_MECHANISM_INFO["mx"][1],
                }
            )
        elif mech.startswith("ptr"):
            rows.append(
                {
                    "tag": "ptr",
                    "value": part,
                    "name": "PTR (Deprecated)",
                    "description": "PTR mechanism is deprecated and should not be used.",
                }
            )
        elif mech.startswith("exists:"):
            rows.append(
                {
                    "tag": "exists",
                    "value": mech[7:],
                    "name": f"Exists ({qual_label})",
                    "description": SPF_MECHANISM_INFO["exists"][1],
                }
            )
        elif mech == "all":
            rows.append(
                {
                    "tag": "all",
                    "value": part,
                    "name": f"All ({qual_label})",
                    "description": f"Default action for non-matching senders: {qual_label}.",
                }
            )
    return rows


def _count_spf_lookups(record: str, depth: int = 0, seen: set | None = None) -> tuple[int, list[str]]:
    """Recursively count DNS lookups in SPF record. Max 10 allowed by RFC 7208."""
    if seen is None:
        seen = set()
    if depth > 10:
        return 0, ["Recursion depth exceeded — possible SPF loop"]

    lookup_count = 0
    warnings = []
    parts = record.split()

    for part in parts:
        _, mech = _strip_qualifier(part)
        resolve_target = None

        if mech.startswith("include:"):
            resolve_target = mech[8:]
            lookup_count += 1
        elif mech.startswith("redirect="):
            resolve_target = mech[9:]
            lookup_count += 1
        elif (
            mech == "a"
            or mech.startswith("a:")
            or mech.startswith("a/")
            or mech == "mx"
            or mech.startswith("mx:")
            or mech.startswith("mx/")
            or mech.startswith("ptr")
            or mech.startswith("exists:")
        ):
            lookup_count += 1

        # Recursively resolve includes/redirects
        if resolve_target and resolve_target not in seen:
            seen.add(resolve_target)
            try:
                sub_records = _resolve_txt(resolve_target)
                sub_spf = [r for r in sub_records if r.startswith("v=spf1")]
                if sub_spf:
                    sub_count, sub_warnings = _count_spf_lookups(sub_spf[0], depth + 1, seen)
                    lookup_count += sub_count
                    warnings.extend(sub_warnings)
            except _DnsLookupFailed:
                warnings.append(f"DNS lookup failed for {resolve_target} — lookup count may be incomplete")
            except Exception:
                warnings.append(f"Could not resolve: {resolve_target}")

    return lookup_count, warnings


def _check_spf(domain: str) -> dict[str, Any]:
    """Full SPF analysis with parsed record + validation tests."""
    result: dict[str, Any] = {
        "raw_record": None,
        "parsed": [],
        "tests": [],
        "grade": "F",
        "lookup_count": 0,
        "lookup_warnings": [],
    }

    try:
        txt_records = _resolve_txt(domain)
    except _DnsLookupFailed as exc:
        result["grade"] = "?"
        result["tests"].append(
            {"test": "SPF Record Published", "pass": False, "result": f"DNS lookup failed — cannot verify SPF ({exc})"}
        )
        return result

    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    # Test 1: Record published?
    if not spf_records:
        result["tests"].append({"test": "SPF Record Published", "pass": False, "result": "No SPF record found"})
        return result

    spf = spf_records[0]
    result["raw_record"] = spf
    result["tests"].append({"test": "SPF Record Published", "pass": True, "result": "SPF record found"})

    # Parse into table
    result["parsed"] = _parse_spf(spf)

    # Test 2: Syntax valid?
    if not spf.startswith("v=spf1"):
        result["tests"].append(
            {"test": "SPF Syntax Check", "pass": False, "result": "Record does not start with v=spf1"}
        )
    else:
        result["tests"].append({"test": "SPF Syntax Check", "pass": True, "result": "The record is valid"})

    # Test 3: Multiple records?
    if len(spf_records) > 1:
        result["tests"].append(
            {
                "test": "SPF Multiple Records",
                "pass": False,
                "result": f"Found {len(spf_records)} SPF records — only one is allowed",
            }
        )
    else:
        result["tests"].append({"test": "SPF Multiple Records", "pass": True, "result": "Only one SPF record found"})

    # Test 4: Lookup count (<= 10)
    lookup_count, lookup_warnings = _count_spf_lookups(spf)
    result["lookup_count"] = lookup_count
    result["lookup_warnings"] = lookup_warnings

    if lookup_count > 10:
        result["tests"].append(
            {
                "test": "SPF Lookup Limit",
                "pass": False,
                "result": f"{lookup_count} DNS lookups found — exceeds the 10-lookup limit (RFC 7208). SPF will fail for some receivers.",
            }
        )
    else:
        result["tests"].append(
            {
                "test": "SPF Lookup Limit",
                "pass": True,
                "result": f"{lookup_count} DNS lookup(s) — within the 10-lookup limit",
            }
        )

    # Test 5: Policy strictness — match as tokens, not substrings
    spf_tokens = spf.split()
    if "-all" in spf_tokens:
        result["tests"].append(
            {"test": "SPF 'all' Policy", "pass": True, "result": "Uses strict fail (-all) — recommended"}
        )
        result["grade"] = "A"
    elif "~all" in spf_tokens:
        result["tests"].append(
            {"test": "SPF 'all' Policy", "pass": True, "result": "Uses soft fail (~all) — consider upgrading to -all"}
        )
        result["grade"] = "B"
    elif "+all" in spf_tokens or "all" in spf_tokens:
        result["tests"].append(
            {
                "test": "SPF 'all' Policy",
                "pass": False,
                "result": "Uses +all — allows ANY server to send as your domain",
            }
        )
        result["grade"] = "F"
    elif "?all" in spf_tokens:
        result["tests"].append(
            {"test": "SPF 'all' Policy", "pass": False, "result": "Uses ?all (neutral) — provides no protection"}
        )
        result["grade"] = "C"
    else:
        result["tests"].append(
            {"test": "SPF 'all' Policy", "pass": False, "result": "No 'all' mechanism found — implicit +all"}
        )
        result["grade"] = "C"

    # Downgrade for lookup limit breach
    if lookup_count > 10 and result["grade"] in ("A", "B"):
        result["grade"] = "C"

    return result


# ═══════════════════════════════════════════════════════════════════
#  DMARC
# ═══════════════════════════════════════════════════════════════════


def _parse_dmarc(record: str) -> list[dict[str, str]]:
    """Parse DMARC record into tag/value table rows."""
    rows = []
    # DMARC tags are semicolon-separated
    tags = [t.strip() for t in record.split(";") if t.strip()]
    for tag in tags:
        if "=" in tag:
            key, _, value = tag.partition("=")
            key = key.strip()
            value = value.strip()
            info = DMARC_TAG_INFO.get(key, (key, f"DMARC tag: {key}"))
            rows.append(
                {
                    "tag": key,
                    "value": value,
                    "name": info[0],
                    "description": info[1],
                }
            )
    return rows


def _check_dmarc(domain: str) -> dict[str, Any]:
    """Full DMARC analysis with parsed record + validation tests."""
    result: dict[str, Any] = {
        "raw_record": None,
        "parsed": [],
        "tests": [],
        "grade": "F",
    }

    try:
        dmarc_records = _resolve_txt(f"_dmarc.{domain}")
    except _DnsLookupFailed as exc:
        result["grade"] = "?"
        result["tests"].append(
            {
                "test": "DMARC Record Published",
                "pass": False,
                "result": f"DNS lookup failed — cannot verify DMARC ({exc})",
            }
        )
        return result

    dmarc_found = [r for r in dmarc_records if r.startswith("v=DMARC1")]

    # Test 1: Record published?
    if not dmarc_found:
        result["tests"].append({"test": "DMARC Record Published", "pass": False, "result": "No DMARC record found"})
        return result

    dmarc = dmarc_found[0]
    result["raw_record"] = dmarc
    result["tests"].append({"test": "DMARC Record Published", "pass": True, "result": "DMARC record found"})

    # Parse into table
    result["parsed"] = _parse_dmarc(dmarc)

    # Test 2: Syntax valid?
    if not dmarc.startswith("v=DMARC1"):
        result["tests"].append(
            {"test": "DMARC Syntax Check", "pass": False, "result": "Record does not start with v=DMARC1"}
        )
    else:
        result["tests"].append({"test": "DMARC Syntax Check", "pass": True, "result": "The record is valid"})

    # Test 3: Multiple records?
    if len(dmarc_found) > 1:
        result["tests"].append(
            {
                "test": "DMARC Multiple Records",
                "pass": False,
                "result": f"Found {len(dmarc_found)} DMARC records — only one is allowed",
            }
        )
    else:
        result["tests"].append({"test": "DMARC Multiple Records", "pass": True, "result": "Single DMARC record found"})

    # Use parsed tags for policy checks (not substring matching)
    tags = {row["tag"]: row["value"] for row in result["parsed"]}

    # Test 4: Policy
    policy = tags.get("p", "").lower()
    if policy == "reject":
        result["tests"].append({"test": "DMARC Policy Enabled", "pass": True, "result": "DMARC Reject policy enabled"})
        result["grade"] = "A"
    elif policy == "quarantine":
        result["tests"].append(
            {"test": "DMARC Policy Enabled", "pass": True, "result": "DMARC Quarantine policy enabled"}
        )
        result["grade"] = "B"
    elif policy == "none":
        result["tests"].append(
            {
                "test": "DMARC Policy Enabled",
                "pass": False,
                "result": "DMARC policy is 'none' — monitoring only, not enforcing",
            }
        )
        result["grade"] = "C"
    else:
        result["tests"].append({"test": "DMARC Policy Enabled", "pass": False, "result": "No policy tag found"})
        result["grade"] = "C"

    # Test 5: Reporting configured?
    has_rua = "rua" in tags
    if has_rua:
        result["tests"].append(
            {"test": "DMARC Reporting", "pass": True, "result": "Aggregate reporting (rua) is configured"}
        )
    else:
        result["tests"].append(
            {
                "test": "DMARC Reporting",
                "pass": False,
                "result": "No aggregate reporting (rua) configured — you won't receive DMARC reports",
            }
        )

    # Test 6: Percentage
    pct_str = tags.get("pct")
    pct_match = re.match(r"(\d+)", pct_str) if pct_str else None
    if pct_match:
        pct = int(pct_match.group(1))
        if pct == 100:
            result["tests"].append(
                {"test": "DMARC Percentage", "pass": True, "result": "Policy applies to 100% of messages"}
            )
        else:
            result["tests"].append(
                {
                    "test": "DMARC Percentage",
                    "pass": True,
                    "result": f"Policy applies to {pct}% of messages — consider increasing to 100",
                }
            )
    else:
        result["tests"].append({"test": "DMARC Percentage", "pass": True, "result": "No pct tag — defaults to 100%"})

    return result


# ═══════════════════════════════════════════════════════════════════
#  DKIM
# ═══════════════════════════════════════════════════════════════════


def _check_dkim(domain: str) -> dict[str, Any]:
    """DKIM analysis — check multiple selectors."""
    result: dict[str, Any] = {
        "found_selectors": [],
        "checked_selectors": DKIM_SELECTORS,
        "tests": [],
        "grade": "C",
    }

    found_any = False
    lookup_failures = 0
    for selector in DKIM_SELECTORS:
        dkim_name = f"{selector}._domainkey.{domain}"
        try:
            records = _resolve_txt(dkim_name)
        except _DnsLookupFailed:
            lookup_failures += 1
            continue
        if records:
            found_any = True
            result["found_selectors"].append(
                {
                    "selector": selector,
                    "record": records[0][:120] + "..." if len(records[0]) > 120 else records[0],
                }
            )

    if found_any:
        selectors = ", ".join(s["selector"] for s in result["found_selectors"])
        result["tests"].append(
            {
                "test": "DKIM Record Published",
                "pass": True,
                "result": f"DKIM record(s) found for selector(s): {selectors}",
            }
        )

        # Check if key looks valid (has p= tag)
        for s in result["found_selectors"]:
            if "p=" in s["record"]:
                result["tests"].append(
                    {
                        "test": f"DKIM Key Valid ({s['selector']})",
                        "pass": True,
                        "result": f"Public key found in selector '{s['selector']}'",
                    }
                )
            else:
                result["tests"].append(
                    {
                        "test": f"DKIM Key Valid ({s['selector']})",
                        "pass": False,
                        "result": f"Selector '{s['selector']}' found but no public key (p=) present",
                    }
                )

        result["grade"] = "A"
    else:
        if lookup_failures == len(DKIM_SELECTORS):
            # All lookups failed — network issue, not missing records
            result["tests"].append(
                {
                    "test": "DKIM Record Published",
                    "pass": False,
                    "result": f"DNS lookups failed for all {len(DKIM_SELECTORS)} selectors — cannot verify DKIM",
                }
            )
            result["grade"] = "?"
        else:
            result["tests"].append(
                {
                    "test": "DKIM Record Published",
                    "pass": False,
                    "result": f"No DKIM record found (checked {len(DKIM_SELECTORS)} common selectors — may use a custom selector)",
                }
            )
            result["grade"] = "C"

    return result


# ═══════════════════════════════════════════════════════════════════
#  MX DEEP CHECK
# ═══════════════════════════════════════════════════════════════════

FREE_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.uk",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "mail.com",
    "protonmail.com",
    "proton.me",
    "zoho.com",
    "yandex.com",
    "gmx.com",
    "gmx.net",
    "fastmail.com",
    "tutanota.com",
    "hey.com",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "throwaway.email",
    "yopmail.com",
    "sharklasers.com",
    "guerrillamailblock.com",
    "grr.la",
    "dispostable.com",
    "trashmail.com",
    "10minutemail.com",
    "getnada.com",
    "maildrop.cc",
    "mailnesia.com",
    "tmpmail.org",
    "temp-mail.org",
    "fakeinbox.com",
    "emailondeck.com",
    "33mail.com",
    "mytemp.email",
}


def _smtp_check(mx_host: str, domain: str) -> dict[str, Any]:
    """Connect to MX host on port 25 and check SMTP banner + RCPT acceptance."""
    import smtplib

    result: dict[str, Any] = {
        "host": mx_host,
        "reachable": False,
        "banner": None,
        "supports_starttls": False,
        "catch_all": None,
    }

    try:
        smtp = smtplib.SMTP(timeout=10)
        code, banner = smtp.connect(mx_host, 25)
        result["reachable"] = True
        result["banner"] = banner.decode(errors="replace")[:200]

        # Check STARTTLS
        try:
            smtp.ehlo()
            if smtp.has_extn("starttls"):
                result["supports_starttls"] = True
        except Exception:
            pass

        # Catch-all detection: try a random address
        try:
            smtp.ehlo(domain)
            smtp.mail(f"test@{domain}")
            import random
            import string

            random_user = "".join(random.choices(string.ascii_lowercase, k=20))
            code, _ = smtp.rcpt(f"{random_user}@{domain}")
            result["catch_all"] = code == 250
        except Exception:
            result["catch_all"] = None

        smtp.quit()
    except Exception:
        pass

    return result


def _check_mx(domain: str) -> dict[str, Any]:
    """Deep MX analysis — hosts, SMTP check, provider detection."""
    result: dict[str, Any] = {
        "mx_records": [],
        "smtp_checks": [],
        "is_free_provider": False,
        "is_disposable": False,
        "provider_name": None,
        "tests": [],
        "parsed": [],
        "grade": "F",
    }

    # Get MX records
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
        mx_records = []
        for rdata in answers:
            mx_records.append(
                {
                    "priority": rdata.preference,
                    "host": str(rdata.exchange).rstrip("."),
                }
            )
        mx_records.sort(key=lambda x: x["priority"])
        result["mx_records"] = mx_records
    except Exception:
        result["tests"].append(
            {"test": "MX Record Exists", "pass": False, "result": "No MX records found — domain cannot receive email"}
        )
        return result

    if not mx_records:
        result["tests"].append({"test": "MX Record Exists", "pass": False, "result": "No MX records found"})
        return result

    result["tests"].append(
        {"test": "MX Record Exists", "pass": True, "result": f"Found {len(mx_records)} MX record(s)"}
    )

    # Parsed table of MX records
    result["parsed"] = [
        {
            "tag": str(mx["priority"]),
            "value": mx["host"],
            "name": "Priority",
            "description": f"Mail server at priority {mx['priority']}",
        }
        for mx in mx_records
    ]

    # Provider detection
    primary_mx = mx_records[0]["host"].lower()
    if "google" in primary_mx or "gmail" in primary_mx:
        result["provider_name"] = "Google Workspace"
    elif "outlook" in primary_mx or "microsoft" in primary_mx:
        result["provider_name"] = "Microsoft 365"
    elif "mimecast" in primary_mx:
        result["provider_name"] = "Mimecast"
    elif "proofpoint" in primary_mx or "pphosted" in primary_mx:
        result["provider_name"] = "Proofpoint"
    elif "barracuda" in primary_mx:
        result["provider_name"] = "Barracuda"
    elif "zoho" in primary_mx:
        result["provider_name"] = "Zoho Mail"

    if result["provider_name"]:
        result["tests"].append(
            {"test": "Email Provider", "pass": True, "result": f"Detected: {result['provider_name']}"}
        )

    # Free/disposable checks
    result["is_free_provider"] = domain.lower() in FREE_PROVIDERS
    result["is_disposable"] = domain.lower() in DISPOSABLE_DOMAINS

    if result["is_disposable"]:
        result["tests"].append(
            {"test": "Disposable Domain", "pass": False, "result": "Domain is a known disposable email service"}
        )
    else:
        result["tests"].append(
            {"test": "Disposable Domain", "pass": True, "result": "Domain is not a disposable email service"}
        )

    if result["is_free_provider"]:
        result["tests"].append(
            {"test": "Free Provider", "pass": True, "result": "Domain is a free email provider (Gmail, Yahoo, etc.)"}
        )

    # SMTP check on primary MX
    primary = mx_records[0]["host"]
    smtp = _smtp_check(primary, domain)
    result["smtp_checks"].append(smtp)

    if smtp["reachable"]:
        result["tests"].append(
            {"test": "SMTP Reachable", "pass": True, "result": f"Primary MX ({primary}) accepts connections on port 25"}
        )
    else:
        result["tests"].append(
            {"test": "SMTP Reachable", "pass": False, "result": f"Primary MX ({primary}) not reachable on port 25"}
        )

    if smtp["supports_starttls"]:
        result["tests"].append(
            {"test": "STARTTLS Support", "pass": True, "result": "Mail server supports STARTTLS encryption"}
        )
    else:
        result["tests"].append(
            {
                "test": "STARTTLS Support",
                "pass": False,
                "result": "Mail server does not support STARTTLS — mail sent in cleartext",
            }
        )

    if smtp["catch_all"] is True:
        result["tests"].append(
            {"test": "Catch-All Detection", "pass": True, "result": "Domain accepts all addresses (catch-all enabled)"}
        )
    elif smtp["catch_all"] is False:
        result["tests"].append(
            {"test": "Catch-All Detection", "pass": True, "result": "Domain rejects unknown addresses (no catch-all)"}
        )

    # Grade
    if smtp["reachable"] and smtp["supports_starttls"]:
        result["grade"] = "A"
    elif smtp["reachable"]:
        result["grade"] = "B"
    else:
        result["grade"] = "C"

    return result


# ═══════════════════════════════════════════════════════════════════
#  MAIN SCAN
# ═══════════════════════════════════════════════════════════════════


def _has_mx(domain: str) -> bool:
    """Return True if the domain has at least one MX record."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
        return any(True for _ in answers)
    except Exception:
        return False


def scan(domain: str) -> ScanResult:
    start = time.time()
    findings = []
    raw_data: dict[str, Any] = {}

    # ── Pre-check: does the domain receive email at all? ──
    if not _has_mx(domain):
        return ScanResult(
            module="email",
            status="warn",
            grade="C",
            findings=[
                {
                    "label": "MX Records",
                    "value": "Not found",
                    "grade": "C",
                    "detail": f"No MX records found for {domain} — domain does not appear to receive email",
                    "fix": "Add MX records if this domain should receive email, or ignore if email is not used",
                }
            ],
            raw_data={"mx_exists": False},
            elapsed=time.time() - start,
            retries=0,
        )

    # ── SPF ──
    spf = _check_spf(domain)
    raw_data["spf"] = spf
    spf_fix = ""
    if spf["grade"] == "?":
        spf_fix = "DNS lookup failed — retry scan to verify SPF"
    elif spf["grade"] == "F":
        spf_fix = "Add a TXT record: v=spf1 include:_spf.google.com -all (adjust for your provider)"
    elif spf["grade"] in ("B", "C"):
        spf_fix = 'Update SPF to use "-all" instead of "~all"'

    findings.append(
        {
            "label": "SPF",
            "value": spf["raw_record"] or ("Lookup failed" if spf["grade"] == "?" else "Not found"),
            "grade": spf["grade"],
            "detail": spf["tests"][-1]["result"] if spf["tests"] else "No SPF record",
            "fix": spf_fix,
            "parsed_record": spf["parsed"],
            "tests": spf["tests"],
            "record_type": "SPF",
            "domain": domain,
        }
    )

    # ── DMARC ──
    dmarc = _check_dmarc(domain)
    raw_data["dmarc"] = dmarc
    dmarc_fix = ""
    if dmarc["grade"] == "?":
        dmarc_fix = "DNS lookup failed — retry scan to verify DMARC"
    elif dmarc["grade"] == "F":
        dmarc_fix = f"Add TXT record at _dmarc.{domain}: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"
    elif dmarc["grade"] in ("B", "C"):
        dmarc_fix = "Upgrade DMARC policy to p=reject after monitoring"

    findings.append(
        {
            "label": "DMARC",
            "value": dmarc["raw_record"] or ("Lookup failed" if dmarc["grade"] == "?" else "Not found"),
            "grade": dmarc["grade"],
            "detail": dmarc["tests"][-1]["result"] if dmarc["tests"] else "No DMARC record",
            "fix": dmarc_fix,
            "parsed_record": dmarc["parsed"],
            "tests": dmarc["tests"],
            "record_type": "DMARC",
            "domain": domain,
        }
    )

    # ── DKIM ──
    dkim = _check_dkim(domain)
    raw_data["dkim"] = dkim
    if dkim["grade"] == "?":
        dkim_fix = "DNS lookups failed — retry scan to verify DKIM"
    elif dkim["grade"] != "A":
        dkim_fix = (
            "Verify DKIM is configured — if using a custom selector not in our list, this check may not detect it"
        )
    else:
        dkim_fix = ""

    findings.append(
        {
            "label": "DKIM",
            "value": f"{len(dkim['found_selectors'])} selector(s) found" if dkim["found_selectors"] else "Not found",
            "grade": dkim["grade"],
            "detail": dkim["tests"][0]["result"] if dkim["tests"] else "No DKIM record",
            "fix": dkim_fix,
            "parsed_record": [],
            "tests": dkim["tests"],
            "record_type": "DKIM",
            "domain": domain,
        }
    )

    # ── MX Deep Check ──
    mx = _check_mx(domain)
    raw_data["mx"] = mx
    mx_fix = ""
    if mx["grade"] == "F":
        mx_fix = "Add MX records for your domain to receive email"
    elif mx["grade"] == "B":
        mx_fix = "Enable STARTTLS on your mail server for encrypted delivery"
    elif mx["grade"] == "C":
        mx_fix = "Verify your MX host is reachable on port 25"

    mx_detail = mx["tests"][0]["result"] if mx["tests"] else "No MX records"
    findings.append(
        {
            "label": "MX / Mail Server",
            "value": mx["mx_records"] or "Not found",
            "grade": mx["grade"],
            "detail": mx_detail,
            "fix": mx_fix,
            "parsed_record": mx["parsed"],
            "tests": mx["tests"],
            "record_type": "MX / Mail Server",
            "domain": domain,
        }
    )

    grades = [f["grade"] for f in findings if f["grade"] not in ("?", "-")]
    module_grade = worst_grade(grades) if grades else "?"
    status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

    return ScanResult(
        module="email",
        status=status,
        grade=module_grade,
        findings=findings,
        raw_data=raw_data,
        elapsed=time.time() - start,
        retries=0,
    )
