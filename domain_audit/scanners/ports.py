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
ACCEPTABLE_PORTS = {22, 25, 8080, 8443}
DANGEROUS_PORTS = {1433, 3306, 3389, 5432, 9200, 9300, 27017, 27018, 27019}

PORT_TIMEOUT = 3.0


def _check_port(host: str, port: int) -> tuple[int, bool]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(PORT_TIMEOUT)
    try:
        result = sock.connect_ex((host, port))
        return port, result == 0
    except (socket.timeout, OSError):
        return port, False
    finally:
        sock.close()


def _scan_host(host: str) -> dict[str, Any] | None:
    """Resolve and port-scan a single host. Returns None if unresolvable/private."""
    try:
        ip = socket.gethostbyname(host)
        validate_resolved_ip(ip, host)
    except (PrivateIPError, socket.gaierror):
        return None

    open_ports: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_check_port, host, port): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append({"port": port, "service": COMMON_PORTS[port]})

    open_ports.sort(key=lambda x: x["port"])
    return {"host": host, "ip": ip, "open_ports": open_ports}


def _grade_ports(open_port_numbers: set[int]) -> str:
    dangerous_open = open_port_numbers & DANGEROUS_PORTS
    if dangerous_open:
        return "F"
    unexpected_open = open_port_numbers - EXPECTED_PORTS - ACCEPTABLE_PORTS - DANGEROUS_PORTS
    if unexpected_open:
        return "C"
    if open_port_numbers <= EXPECTED_PORTS:
        return "A"
    if open_port_numbers <= EXPECTED_PORTS | ACCEPTABLE_PORTS:
        return "B"
    return "A"


def scan(domain: str, subdomains: list[str] | None = None) -> ScanResult:
    start = time.time()
    findings: list[dict[str, Any]] = []
    raw_data: dict[str, Any] = {}

    # Build list of all hosts to scan
    hosts = [domain]
    if subdomains:
        hosts.extend(sub for sub in subdomains if sub != domain)

    # Scan all hosts in parallel
    host_results: list[dict[str, Any]] = []
    skipped: list[str] = []

    with ThreadPoolExecutor(max_workers=min(len(hosts), 8)) as executor:
        futures = {executor.submit(_scan_host, h): h for h in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
                if result:
                    host_results.append(result)
                else:
                    skipped.append(host)
            except Exception:
                skipped.append(host)

    host_results.sort(key=lambda r: (r["host"] != domain, r["host"]))

    if not host_results:
        return ScanResult(
            module="ports",
            status="error",
            grade="?",
            findings=[{
                "label": "Port scan",
                "value": "No resolvable hosts",
                "grade": "?",
                "detail": "Could not resolve any hosts to a public IP",
                "fix": "Verify domain has a valid A record",
            }],
            raw_data={"error": "No resolvable hosts", "skipped": skipped},
            elapsed=time.time() - start,
            retries=0,
        )

    raw_data["hosts_scanned"] = len(host_results)
    raw_data["hosts_skipped"] = skipped
    raw_data["host_results"] = host_results

    # Aggregate all open ports across all hosts for overall grade
    all_open: set[int] = set()
    hosts_with_dangerous: list[str] = []

    for hr in host_results:
        port_nums = {p["port"] for p in hr["open_ports"]}
        all_open |= port_nums
        if port_nums & DANGEROUS_PORTS:
            hosts_with_dangerous.append(hr["host"])

    module_grade = _grade_ports(all_open)

    # Findings per host
    for hr in host_results:
        host_label = hr["host"]
        port_nums = {p["port"] for p in hr["open_ports"]}
        dangerous_open = port_nums & DANGEROUS_PORTS

        if dangerous_open:
            port_names = ", ".join(f"{p} ({COMMON_PORTS[p]})" for p in sorted(dangerous_open))
            findings.append({
                "label": f"Dangerous ports — {host_label}",
                "value": list(dangerous_open),
                "grade": "F",
                "detail": f"Database/RDP ports open: {port_names}",
                "fix": "Close these ports or restrict access via firewall rules",
            })

        unexpected = port_nums - EXPECTED_PORTS - ACCEPTABLE_PORTS - DANGEROUS_PORTS
        if unexpected:
            port_names = ", ".join(f"{p} ({COMMON_PORTS.get(p, 'unknown')})" for p in sorted(unexpected))
            findings.append({
                "label": f"Unexpected ports — {host_label}",
                "value": list(unexpected),
                "grade": "C",
                "detail": f"Non-standard ports open: {port_names}",
                "fix": "Review if these ports need to be publicly accessible",
            })

        if hr["open_ports"]:
            findings.append({
                "label": f"Open ports — {host_label}",
                "value": hr["open_ports"],
                "grade": "-",
                "detail": "{} port(s): {}".format(
                    len(hr["open_ports"]),
                    ", ".join("{}/{}".format(p["port"], p["service"]) for p in hr["open_ports"]),
                ),
                "fix": "",
            })
        else:
            findings.append({
                "label": f"Open ports — {host_label}",
                "value": [],
                "grade": "-",
                "detail": "No common ports appear open (may be filtered)",
                "fix": "",
            })

    # Summary finding
    if len(host_results) > 1:
        findings.insert(0, {
            "label": "Hosts scanned",
            "value": len(host_results),
            "grade": "-",
            "detail": f"Scanned {len(host_results)} host(s): {', '.join(hr['host'] for hr in host_results)}",
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
