from __future__ import annotations

import time
from typing import Any

import dns.resolver
import dns.exception
import dns.query
import dns.zone
import dns.rdatatype

from domain_audit.grader import ScanResult, worst_grade
from domain_audit.retry import RetryConfig, with_retry

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]
CRITICAL_TYPES = {"A", "NS"}
IMPORTANT_TYPES = {"MX", "SOA"}

_retry = RetryConfig(max_retries=3, timeout_per_attempt=5.0)


@with_retry(config=_retry)
def _resolve(domain: str, rdtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rdtype, lifetime=_retry.timeout_per_attempt)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []


def _check_zone_transfer(domain: str) -> dict[str, Any]:
    """Test if AXFR zone transfer is allowed — serious security issue."""
    result: dict[str, Any] = {
        "vulnerable": False,
        "nameservers_tested": [],
        "vulnerable_ns": [],
    }

    try:
        ns_records = _resolve(domain, "NS")
        for ns in ns_records:
            ns = ns.rstrip(".")
            result["nameservers_tested"].append(ns)
            try:
                # Resolve NS to IP
                ns_ips = _resolve(ns, "A")
                for ns_ip in ns_ips:
                    try:
                        zone = dns.zone.from_xfr(
                            dns.query.xfr(ns_ip, domain, timeout=5.0, lifetime=5.0)
                        )
                        if zone:
                            result["vulnerable"] = True
                            result["vulnerable_ns"].append(ns)
                            break
                    except Exception:
                        pass  # Transfer refused = good
            except Exception:
                pass
    except Exception:
        pass

    return result


def _parse_caa(records: list[str]) -> list[dict[str, str]]:
    """Parse CAA records into structured data."""
    parsed = []
    for record in records:
        parts = record.split(None, 2)
        if len(parts) >= 3:
            flags = parts[0]
            tag = parts[1].strip('"')
            value = parts[2].strip('"')
            desc = {
                "issue": "Authorized Certificate Authority for this domain",
                "issuewild": "Authorized CA for wildcard certificates",
                "iodef": "URL for reporting certificate issue violations",
            }.get(tag, f"CAA tag: {tag}")
            parsed.append({
                "flags": flags,
                "tag": tag,
                "value": value,
                "description": desc,
            })
    return parsed


def scan(domain: str) -> ScanResult:
    start = time.time()
    findings = []
    raw_data: dict[str, Any] = {}
    total_retries = 0

    # ── Standard record types ──
    for rdtype in RECORD_TYPES:
        try:
            records = _resolve(domain, rdtype)
            raw_data[rdtype] = records
            found = len(records) > 0

            if rdtype == "CAA":
                # Special handling for CAA
                if found:
                    parsed_caa = _parse_caa(records)
                    raw_data["caa_parsed"] = parsed_caa
                    findings.append({
                        "label": "CAA records",
                        "value": records,
                        "grade": "A",
                        "detail": f"CAA record(s) found — restricts which CAs can issue certificates",
                        "fix": "",
                        "parsed_record": [
                            {"tag": p["tag"], "value": p["value"], "name": f"Flags: {p['flags']}", "description": p["description"]}
                            for p in parsed_caa
                        ],
                        "tests": [
                            {"test": "CAA Record Published", "pass": True, "result": f"Found {len(parsed_caa)} CAA record(s)"},
                            {"test": "Issue Tag Present", "pass": any(p["tag"] == "issue" for p in parsed_caa),
                             "result": "Authorized CAs specified" if any(p["tag"] == "issue" for p in parsed_caa) else "No 'issue' tag — any CA can issue certs"},
                        ],
                        "record_type": "CAA",
                        "domain": domain,
                    })
                else:
                    findings.append({
                        "label": "CAA records",
                        "value": "Not found",
                        "grade": "C",
                        "detail": "No CAA record — any CA can issue certificates for this domain",
                        "fix": "Add CAA record: 0 issue \"letsencrypt.org\" (adjust for your CA)",
                        "tests": [
                            {"test": "CAA Record Published", "pass": False, "result": "No CAA record found — any Certificate Authority can issue certs for this domain"},
                        ],
                        "record_type": "CAA",
                        "domain": domain,
                    })
            else:
                grade = "A" if found else _missing_grade(rdtype)
                findings.append({
                    "label": f"{rdtype} records",
                    "value": records if found else "Not found",
                    "grade": grade,
                    "detail": f"{'Found' if found else 'Missing'} {rdtype} record{'s' if len(records) != 1 else ''}",
                    "fix": _fix_suggestion(rdtype) if not found else "",
                })
        except Exception as exc:
            raw_data[rdtype] = str(exc)
            findings.append({
                "label": f"{rdtype} records",
                "value": f"Error: {exc}",
                "grade": "?",
                "detail": f"Could not query {rdtype}: {exc}",
                "fix": "",
            })

    # ── Zone transfer test ──
    zt = _check_zone_transfer(domain)
    raw_data["zone_transfer"] = zt

    if zt["vulnerable"]:
        ns_list = ", ".join(zt["vulnerable_ns"])
        findings.append({
            "label": "DNS Zone Transfer",
            "value": f"VULNERABLE: {ns_list}",
            "grade": "F",
            "detail": f"Zone transfer (AXFR) is OPEN on: {ns_list} — exposes all DNS records",
            "fix": "Disable AXFR on your nameservers or restrict to authorized secondary NS only",
            "tests": [
                {"test": "Zone Transfer (AXFR)", "pass": False, "result": f"AXFR allowed on {ns_list} — all DNS records are exposed to anyone"},
            ],
            "record_type": "Zone Transfer",
            "domain": domain,
        })
    else:
        tested = ", ".join(zt["nameservers_tested"]) if zt["nameservers_tested"] else "none found"
        findings.append({
            "label": "DNS Zone Transfer",
            "value": "Not vulnerable",
            "grade": "A",
            "detail": f"Zone transfer (AXFR) properly restricted",
            "fix": "",
            "tests": [
                {"test": "Zone Transfer (AXFR)", "pass": True, "result": f"AXFR correctly denied (tested: {tested})"},
            ],
            "record_type": "Zone Transfer",
            "domain": domain,
        })

    grades = [f["grade"] for f in findings if f["grade"] not in ("?", "-")]
    module_grade = worst_grade(grades) if grades else "?"
    status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

    return ScanResult(
        module="dns",
        status=status,
        grade=module_grade,
        findings=findings,
        raw_data=raw_data,
        elapsed=time.time() - start,
        retries=total_retries,
    )


def _missing_grade(rdtype: str) -> str:
    if rdtype in CRITICAL_TYPES:
        return "F"
    if rdtype in IMPORTANT_TYPES:
        return "C"
    return "A"


def _fix_suggestion(rdtype: str) -> str:
    suggestions = {
        "A": "Add an A record pointing to your server's IPv4 address",
        "AAAA": "Consider adding an AAAA record for IPv6 support",
        "MX": "Add MX records to enable email delivery for your domain",
        "NS": "NS records are critical — contact your DNS provider",
        "TXT": "",
        "CNAME": "",
        "SOA": "SOA record should exist — contact your DNS provider",
        "SRV": "",
    }
    return suggestions.get(rdtype, "")


