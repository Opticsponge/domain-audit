from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from domain_audit.grader import ScanResult
from domain_audit.validators import validate_resolved_ip, PrivateIPError, safe_error

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    27019: "MongoDB-Config",
}

EXPECTED_PORTS = {80, 443}
ACCEPTABLE_PORTS = {22, 25}
DANGEROUS_PORTS = {1433, 3306, 3389, 5432, 9200, 9300, 27017, 27018, 27019}

PORT_TIMEOUT = 3.0


def _check_port(domain: str, port: int) -> tuple[int, bool]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(PORT_TIMEOUT)
    try:
        result = sock.connect_ex((domain, port))
        return port, result == 0
    except (socket.timeout, OSError):
        return port, False
    finally:
        sock.close()


def scan(domain: str) -> ScanResult:
    start = time.time()
    findings = []
    raw_data: dict[str, Any] = {}
    open_ports: list[dict[str, Any]] = []

    # Resolve domain to IP first
    try:
        ip = socket.gethostbyname(domain)
        validate_resolved_ip(ip, domain)
        raw_data["resolved_ip"] = ip
    except PrivateIPError as exc:
        return ScanResult(
            module="ports",
            status="error",
            grade="?",
            findings=[{
                "label": "Port scan",
                "value": "Blocked",
                "grade": "?",
                "detail": str(exc),
                "fix": "Only publicly-routable domains can be scanned",
            }],
            raw_data={"error": str(exc)},
            elapsed=time.time() - start,
            retries=0,
        )
    except socket.gaierror as exc:
        return ScanResult(
            module="ports",
            status="error",
            grade="?",
            findings=[{
                "label": "Port scan",
                "value": f"Error: {safe_error(exc)}",
                "grade": "?",
                "detail": f"Could not resolve domain: {safe_error(exc)}",
                "fix": "Verify domain has a valid A record",
            }],
            raw_data={"error": safe_error(exc)},
            elapsed=time.time() - start,
            retries=0,
        )

    # Scan ports in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_check_port, domain, port): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append({
                    "port": port,
                    "service": COMMON_PORTS[port],
                })

    open_ports.sort(key=lambda x: x["port"])
    open_port_numbers = {p["port"] for p in open_ports}
    raw_data["open_ports"] = open_ports

    # Grade based on what's open
    dangerous_open = open_port_numbers & DANGEROUS_PORTS
    unexpected_open = open_port_numbers - EXPECTED_PORTS - ACCEPTABLE_PORTS - DANGEROUS_PORTS

    if dangerous_open:
        module_grade = "F"
        port_names = ", ".join(f"{p} ({COMMON_PORTS[p]})" for p in sorted(dangerous_open))
        findings.append({
            "label": "Dangerous ports exposed",
            "value": list(dangerous_open),
            "grade": "F",
            "detail": f"Database/RDP ports open to internet: {port_names}",
            "fix": "Close these ports or restrict access via firewall rules",
        })
    elif unexpected_open:
        module_grade = "C"
        port_names = ", ".join(f"{p} ({COMMON_PORTS.get(p, 'unknown')})" for p in sorted(unexpected_open))
        findings.append({
            "label": "Unexpected ports open",
            "value": list(unexpected_open),
            "grade": "C",
            "detail": f"Non-standard ports open: {port_names}",
            "fix": "Review if these ports need to be publicly accessible",
        })
    elif open_port_numbers <= EXPECTED_PORTS | ACCEPTABLE_PORTS:
        module_grade = "A" if open_port_numbers <= EXPECTED_PORTS else "B"
    else:
        module_grade = "A"

    # List all open ports as informational
    if open_ports:
        findings.append({
            "label": "Open ports",
            "value": open_ports,
            "grade": "-",
            "detail": "{} port(s) open: {}".format(len(open_ports), ", ".join("{}/{}".format(p["port"], p["service"]) for p in open_ports)),
            "fix": "",
        })
    else:
        findings.append({
            "label": "Open ports",
            "value": [],
            "grade": "-",
            "detail": "No common ports appear open (may be filtered)",
            "fix": "",
        })

    status = "pass" if module_grade == "A" else "warn" if module_grade in ("B", "C") else "fail"

    return ScanResult(
        module="ports",
        status=status,
        grade=module_grade,
        findings=findings,
        raw_data=raw_data,
        elapsed=time.time() - start,
        retries=0,
    )
