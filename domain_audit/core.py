from __future__ import annotations

import io
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from domain_audit.grader import ScanResult, compute_overall_grade, generate_action_items
from domain_audit.scanners import SCANNERS


class AuditResult:
    """Structured audit result — AI-friendly with clean JSON serialization."""

    def __init__(
        self,
        domain: str,
        results: dict[str, ScanResult],
        overall_grade: str,
        action_items: list[dict[str, str]],
        elapsed: float,
    ):
        self.domain = domain
        self.results = results
        self.overall_grade = overall_grade
        self.action_items = action_items
        self.elapsed = elapsed

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "overall_grade": self.overall_grade,
            "elapsed_seconds": round(self.elapsed, 2),
            "modules": {
                name: result.to_dict() for name, result in self.results.items()
            },
            "action_items": self.action_items,
        }

    def to_json(self, path: str) -> None:
        import json
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    def to_csv(self, path: str) -> None:
        with open(path, "w", newline="") as f:
            f.write(self.to_csv_string())

    def to_csv_string(self) -> str:
        import csv
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["module", "grade", "status", "finding", "detail", "fix"])
        for name, result in self.results.items():
            for finding in result.findings:
                writer.writerow([
                    name,
                    finding.get("grade", "-"),
                    result.status,
                    finding.get("label", ""),
                    finding.get("detail", ""),
                    finding.get("fix", ""),
                ])
        return buf.getvalue()

    def __repr__(self) -> str:
        return f"AuditResult(domain={self.domain!r}, grade={self.overall_grade!r})"


def audit(
    domain: str,
    only: list[str] | None = None,
    max_workers: int = 8,
    show: bool = True,
    deep_subdomains: bool = False,
) -> AuditResult:
    """Run domain audit. Set deep_subdomains=True to probe each subdomain for DNS/SSL/HTTP (slower)."""
    start = time.time()

    # Select scanners
    if only:
        scanner_map = {k: v for k, v in SCANNERS.items() if k in only}
    else:
        scanner_map = SCANNERS

    results: dict[str, ScanResult] = {}

    # Run scanners in parallel
    # Subdomain scanner gets the deep flag
    def _make_scanner_call(name, scan_func, domain):
        if name == "subdomains":
            return scan_func(domain, deep=deep_subdomains)
        return scan_func(domain)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_name = {
            executor.submit(_make_scanner_call, name, scan_func, domain): name
            for name, scan_func in scanner_map.items()
        }

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = ScanResult(
                    module=name,
                    status="error",
                    grade="?",
                    findings=[{
                        "label": f"{name} scanner",
                        "value": f"Unexpected error: {exc}",
                        "grade": "?",
                        "detail": str(exc),
                        "fix": "",
                    }],
                    raw_data={"error": str(exc)},
                )

    overall_grade = compute_overall_grade(results)
    action_items = generate_action_items(results)
    elapsed = time.time() - start

    audit_result = AuditResult(
        domain=domain,
        results=results,
        overall_grade=overall_grade,
        action_items=action_items,
        elapsed=elapsed,
    )

    if show:
        from domain_audit.report import display
        display(audit_result)

    return audit_result
