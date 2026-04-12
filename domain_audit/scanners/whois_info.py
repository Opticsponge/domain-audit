from __future__ import annotations

import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import whois

from domain_audit.grader import ScanResult, worst_grade
from domain_audit.rate_limit import throttle
from domain_audit.retry import RetryConfig, with_retry
from domain_audit.validators import safe_error

_retry = RetryConfig(max_retries=3, timeout_per_attempt=10.0)


@with_retry(config=_retry)
def _whois_lookup(domain: str) -> Any:
    return whois.whois(domain)


def _rdap_lookup(domain: str) -> dict[str, Any]:
    """Fallback: RDAP lookup over HTTPS. Works when WHOIS socket is blocked."""
    import requests

    # Step 1: Find the RDAP server for this TLD
    tld = domain.rsplit(".", 1)[-1]
    throttle("https://data.iana.org/rdap/dns.json")
    bootstrap = requests.get("https://data.iana.org/rdap/dns.json", timeout=10.0).json()
    rdap_url = None
    for entry in bootstrap.get("services", []):
        tlds, urls = entry
        if tld in tlds:
            rdap_url = urls[0]
            break

    if not rdap_url:
        raise ValueError(f"No RDAP server found for TLD .{tld}")

    # Step 2: Query RDAP (URL-encode domain to prevent path traversal)
    url = f"{rdap_url.rstrip('/')}/domain/{urllib.parse.quote(domain, safe='')}"
    throttle(url)
    resp = requests.get(url, timeout=10.0, headers={"Accept": "application/rdap+json"})
    resp.raise_for_status()
    data = resp.json()

    # Step 3: Parse into whois-like structure
    result: dict[str, Any] = {
        "registrar": None,
        "registrar_url": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "name": None,
        "org": None,
        "country": None,
        "dnssec": None,
        "whois_server": None,
    }

    # Events (dates)
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date_str = event.get("eventDate", "")
        if date_str:
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except ValueError:
                dt = None
            if action == "registration" and dt:
                result["creation_date"] = dt
            elif action == "expiration" and dt:
                result["expiration_date"] = dt
            elif action == "last changed" and dt:
                result["updated_date"] = dt

    # Status
    result["status"] = data.get("status", [])

    # Nameservers
    for ns in data.get("nameservers", []):
        name = ns.get("ldhName", "")
        if name:
            result["name_servers"].append(name)

    # Entities (registrar, registrant)
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = _rdap_vcard(entity)
            result["registrar"] = vcard.get("fn", None)
            result["registrar_url"] = (
                entity.get("publicIds", [{}])[0].get("identifier") if entity.get("publicIds") else None
            )
        if "registrant" in roles:
            vcard = _rdap_vcard(entity)
            result["name"] = vcard.get("fn", None)
            result["org"] = vcard.get("org", None)
            result["country"] = vcard.get("country", None)

    # DNSSEC
    sec_dns = data.get("secureDNS", {})
    if sec_dns.get("delegationSigned"):
        result["dnssec"] = "signedDelegation"
    else:
        result["dnssec"] = "unsigned"

    return result


def _rdap_vcard(entity: dict) -> dict[str, str]:
    """Extract name/org/country from RDAP entity vCard."""
    info: dict[str, str] = {}
    vcard_array = entity.get("vcardArray", [])
    if len(vcard_array) >= 2:
        for entry in vcard_array[1]:
            if len(entry) >= 4:
                prop = entry[0]
                value = entry[3]
                if prop == "fn":
                    info["fn"] = str(value)
                elif prop == "org":
                    info["org"] = str(value)
                elif prop == "adr" and isinstance(value, list) and len(value) >= 7 and value[6]:
                    # Country is typically last element
                    info["country"] = str(value[6])
    return info


class _RdapAsWhois:
    """Adapter: makes RDAP result look like python-whois result."""

    def __init__(self, data: dict[str, Any]):
        self._data = data

    def __getattr__(self, name: str) -> Any:
        return self._data.get(name)


def scan(domain: str) -> ScanResult:
    start = time.time()
    retries = 0
    findings = []
    raw_data: dict[str, Any] = {}

    try:
        # Try python-whois first, fall back to RDAP
        w = None
        try:
            w = _whois_lookup(domain)
            # Verify we got useful data (some TLDs return empty)
            if not w.registrar and not w.creation_date and not w.expiration_date:
                raise ValueError("WHOIS returned empty data")
            raw_data["source"] = "whois"
        except Exception:
            # Fallback to RDAP
            rdap_data = _rdap_lookup(domain)
            w = _RdapAsWhois(rdap_data)
            raw_data["source"] = "rdap"

        # ── Extract all available WHOIS fields ──
        raw_data["registrar"] = w.registrar
        raw_data["registrar_url"] = getattr(w, "registrar_url", None)
        raw_data["creation_date"] = _date_str(w.creation_date)
        raw_data["expiration_date"] = _date_str(w.expiration_date)
        raw_data["updated_date"] = _date_str(getattr(w, "updated_date", None))
        raw_data["name_servers"] = w.name_servers
        raw_data["status"] = w.status
        raw_data["registrant"] = getattr(w, "name", None) or getattr(w, "org", None)
        raw_data["registrant_country"] = getattr(w, "country", None)
        raw_data["registrant_state"] = getattr(w, "state", None)
        raw_data["emails"] = getattr(w, "emails", None)
        raw_data["dnssec"] = getattr(w, "dnssec", None)
        raw_data["whois_server"] = getattr(w, "whois_server", None)

        # ── Parsed WHOIS table ──
        parsed = []
        if w.registrar:
            parsed.append(
                {"tag": "Registrar", "value": w.registrar, "name": "Registrar", "description": "Domain registrar"}
            )
        if getattr(w, "registrar_url", None):
            parsed.append(
                {
                    "tag": "Registrar URL",
                    "value": str(w.registrar_url),
                    "name": "URL",
                    "description": "Registrar website",
                }
            )
        if raw_data["registrant"]:
            parsed.append(
                {
                    "tag": "Registrant",
                    "value": str(raw_data["registrant"]),
                    "name": "Owner",
                    "description": "Domain registrant (may be privacy-protected)",
                }
            )
        if raw_data["registrant_country"]:
            parsed.append(
                {
                    "tag": "Country",
                    "value": str(raw_data["registrant_country"]),
                    "name": "Country",
                    "description": "Registrant country",
                }
            )
        if raw_data["creation_date"]:
            parsed.append(
                {
                    "tag": "Created",
                    "value": raw_data["creation_date"],
                    "name": "Creation Date",
                    "description": "Domain registration date",
                }
            )
        if raw_data["expiration_date"]:
            parsed.append(
                {
                    "tag": "Expires",
                    "value": raw_data["expiration_date"],
                    "name": "Expiry Date",
                    "description": "Domain expiration date",
                }
            )
        if raw_data["updated_date"]:
            parsed.append(
                {
                    "tag": "Updated",
                    "value": raw_data["updated_date"],
                    "name": "Last Updated",
                    "description": "Last WHOIS record update",
                }
            )
        if raw_data["whois_server"]:
            parsed.append(
                {
                    "tag": "WHOIS Server",
                    "value": str(raw_data["whois_server"]),
                    "name": "Server",
                    "description": "WHOIS server used",
                }
            )

        # Status codes
        status = w.status
        if isinstance(status, str):
            status = [status]
        if status:
            for s in status or []:
                s_clean = s.split()[0] if s else s  # Strip URL after status
                parsed.append(
                    {
                        "tag": "Status",
                        "value": str(s_clean),
                        "name": "EPP Status",
                        "description": _epp_description(s_clean),
                    }
                )

        # DNSSEC
        dnssec = getattr(w, "dnssec", None)
        if dnssec:
            dnssec_str = str(dnssec) if not isinstance(dnssec, list) else ", ".join(str(d) for d in dnssec)
            parsed.append(
                {
                    "tag": "DNSSEC",
                    "value": dnssec_str,
                    "name": "DNSSEC",
                    "description": "DNS Security Extensions status",
                }
            )

        # ── WHOIS tests ──
        tests = []

        # Registrar
        findings.append(
            {
                "label": "WHOIS Record",
                "value": w.registrar or "Unknown",
                "grade": "-",
                "detail": f"Registered with {w.registrar or 'unknown registrar'}",
                "fix": "",
                "parsed_record": parsed,
                "tests": [],
                "record_type": "WHOIS",
                "domain": domain,
            }
        )

        # Domain age
        created = _parse_date(w.creation_date)
        if created:
            now = datetime.now(tz=timezone.utc)
            age_days = (now - created).days
            raw_data["domain_age_days"] = age_days

            if age_days < 30:
                age_detail = f"Domain is only {age_days} days old — very new, potentially suspicious"
            elif age_days < 365:
                age_detail = f"Domain is {age_days} days old ({age_days // 30} months)"
            else:
                years = age_days // 365
                age_detail = f"Domain is {age_days} days old ({years} year{'s' if years != 1 else ''})"

            tests.append({"test": "Domain Age", "pass": age_days >= 180, "result": age_detail})
        else:
            raw_data["domain_age_days"] = None
            tests.append({"test": "Domain Age", "pass": False, "result": "Could not determine domain age"})

        # Domain expiry
        expiry = _parse_date(w.expiration_date)
        if expiry:
            now = datetime.now(tz=timezone.utc)
            days_left = (expiry - now).days
            raw_data["days_to_expiry"] = days_left

            if days_left < 0:
                exp_grade = "F"
                exp_detail = f"Domain EXPIRED {abs(days_left)} days ago"
                exp_fix = "Renew your domain registration immediately"
            elif days_left < 30:
                exp_grade = "F"
                exp_detail = f"Domain expires in {days_left} days — urgent renewal needed"
                exp_fix = "Renew your domain registration immediately"
            elif days_left < 90:
                exp_grade = "C"
                exp_detail = f"Domain expires in {days_left} days"
                exp_fix = "Renew your domain registration soon"
            elif days_left < 180:
                exp_grade = "B"
                exp_detail = f"Domain expires in {days_left} days"
                exp_fix = "Plan domain renewal"
            else:
                exp_grade = "A"
                exp_detail = f"Domain valid for {days_left} more days"
                exp_fix = ""

            tests.append({"test": "Domain Expiry", "pass": days_left > 90, "result": exp_detail})

            findings.append(
                {
                    "label": "Domain expiration",
                    "value": {"expires": _date_str(w.expiration_date), "days_left": days_left},
                    "grade": exp_grade,
                    "detail": exp_detail,
                    "fix": exp_fix,
                }
            )
        else:
            findings.append(
                {
                    "label": "Domain expiration",
                    "value": "Unknown",
                    "grade": "?",
                    "detail": "Could not determine domain expiration date",
                    "fix": "",
                }
            )
            tests.append({"test": "Domain Expiry", "pass": False, "result": "Expiration date unknown"})

        # Privacy protection
        registrant = raw_data.get("registrant", "")
        privacy_keywords = [
            "privacy",
            "proxy",
            "redacted",
            "data protected",
            "whoisguard",
            "domains by proxy",
            "contact privacy",
        ]
        is_private = any(kw in str(registrant).lower() for kw in privacy_keywords) if registrant else False
        raw_data["privacy_protected"] = is_private
        tests.append(
            {
                "test": "Privacy Protection",
                "pass": True,
                "result": "WHOIS privacy protection enabled" if is_private else "Registrant information is public",
            }
        )

        # DNSSEC
        dnssec_val = getattr(w, "dnssec", None)
        dnssec_enabled = False
        if dnssec_val:
            dnssec_str = str(dnssec_val).lower()
            dnssec_enabled = "signed" in dnssec_str or dnssec_str not in ("unsigned", "none", "false", "")
        raw_data["dnssec_enabled"] = dnssec_enabled
        tests.append(
            {
                "test": "DNSSEC",
                "pass": dnssec_enabled,
                "result": "DNSSEC is enabled"
                if dnssec_enabled
                else "DNSSEC is not enabled — vulnerable to DNS spoofing",
            }
        )

        # EPP status codes check
        status_list = w.status or []
        if isinstance(status_list, str):
            status_list = [status_list]
        has_transfer_lock = any("clienttransferprohibited" in s.lower() for s in status_list)
        has_delete_lock = any("clientdeleteprohibited" in s.lower() for s in status_list)
        tests.append(
            {
                "test": "Transfer Lock",
                "pass": has_transfer_lock,
                "result": "Domain is locked against unauthorized transfers"
                if has_transfer_lock
                else "Domain is NOT locked — vulnerable to unauthorized transfer",
            }
        )
        tests.append(
            {
                "test": "Delete Lock",
                "pass": has_delete_lock,
                "result": "Domain is locked against deletion"
                if has_delete_lock
                else "Domain is NOT locked against deletion",
            }
        )

        # Name servers
        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]
        ns = sorted(set(n.lower() for n in ns))
        raw_data["name_servers_clean"] = ns
        tests.append(
            {
                "test": "Name Servers",
                "pass": len(ns) >= 2,
                "result": f"{len(ns)} name server(s) configured" + (" — should have at least 2" if len(ns) < 2 else ""),
            }
        )

        # Attach tests to the WHOIS record finding
        findings[0]["tests"] = tests

        grades = [str(f["grade"]) for f in findings if f["grade"] not in ("?", "-")]
        module_grade = worst_grade(grades) if grades else "?"
        status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

        return ScanResult(
            module="whois",
            status=status,
            grade=module_grade,
            findings=findings,
            raw_data=raw_data,
            elapsed=time.time() - start,
            retries=retries,
        )

    except Exception as exc:
        return ScanResult(
            module="whois",
            status="error",
            grade="?",
            findings=[
                {
                    "label": "WHOIS lookup",
                    "value": f"Error: {safe_error(exc)}",
                    "grade": "?",
                    "detail": f"WHOIS lookup failed: {safe_error(exc)}",
                    "fix": "Domain may not support WHOIS or the WHOIS server is unreachable",
                }
            ],
            raw_data={"error": safe_error(exc)},
            elapsed=time.time() - start,
            retries=retries,
        )


def _parse_date(date_val: Any) -> datetime | None:
    if isinstance(date_val, list):
        date_val = date_val[0] if date_val else None
    if isinstance(date_val, datetime):
        if date_val.tzinfo is None:
            return date_val.replace(tzinfo=timezone.utc)
        return date_val
    return None


def _date_str(date_val: Any) -> str | None:
    if isinstance(date_val, list):
        date_val = date_val[0] if date_val else None
    if isinstance(date_val, datetime):
        return date_val.isoformat()
    return str(date_val) if date_val else None


def _epp_description(status: str) -> str:
    """Human-readable description of EPP status codes."""
    descriptions = {
        "clienttransferprohibited": "Prevents unauthorized domain transfers",
        "clientdeleteprohibited": "Prevents accidental domain deletion",
        "clientupdateprohibited": "Prevents unauthorized WHOIS changes",
        "clienthold": "Domain is suspended by registrar",
        "serverdeleteprohibited": "Registry-level deletion protection",
        "servertransferprohibited": "Registry-level transfer protection",
        "serverupdateprohibited": "Registry-level update protection",
        "serverhold": "Domain is suspended by registry",
        "ok": "Domain is active with no restrictions",
        "active": "Domain is active",
        "addperiod": "Domain was recently registered",
        "autorenewperiod": "Domain is in auto-renew grace period",
        "redemptionperiod": "Domain is in redemption period after expiry",
        "pendingdelete": "Domain is scheduled for deletion",
        "pendingtransfer": "Domain transfer is in progress",
    }
    key = status.lower().split("https://")[0].strip() if status else ""
    return descriptions.get(key, f"EPP status: {status}")
