from __future__ import annotations

import io
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from domain_audit.colab import is_colab, make_progress_colab
from domain_audit.grader import ScanResult, compute_overall_grade, generate_action_items
from domain_audit.scanners import SCANNERS
from domain_audit.validators import safe_error

# Human-friendly names for progress display
_MODULE_LABELS = {
    "ssl": "SSL/TLS",
    "dns": "DNS Records",
    "subdomains": "Subdomains",
    "headers": "HTTP Headers",
    "whois": "WHOIS",
    "email": "Email Security",
    "ports": "Open Ports",
    "tech": "Tech Stack",
}

# Status icons
_STATUS_ICON = {
    "pass": "\u2705",  # green check
    "warn": "\u26a0\ufe0f",  # warning
    "fail": "\u274c",  # red X
    "error": "\u274c",  # red X
}


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
            "modules": {name: result.to_dict() for name, result in self.results.items()},
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
                writer.writerow(
                    [
                        name,
                        finding.get("grade", "-"),
                        result.status,
                        finding.get("label", ""),
                        finding.get("detail", ""),
                        finding.get("fix", ""),
                    ]
                )
        return buf.getvalue()

    def __repr__(self) -> str:
        return f"AuditResult(domain={self.domain!r}, grade={self.overall_grade!r})"


# ═══════════════════════════════════════════════════════════════════
#  Progress tracking
# ═══════════════════════════════════════════════════════════════════


def _make_progress_terminal(domain: str, scanner_names: list[str]) -> Callable[[str, ScanResult | None], None]:
    """Return a callback that prints scanner progress to the terminal."""
    from rich.console import Console

    console = Console()
    total = len(scanner_names)
    done_count = [0]  # mutable counter for closure

    console.print()
    console.print(f"  [bold white on blue]  SCANNING  [/]  [bold]{domain}[/]  ({total} modules)")
    console.print()

    def callback(name: str, result: ScanResult | None) -> None:
        if result is None:
            # Scanner starting
            return
        done_count[0] += 1
        label = _MODULE_LABELS.get(name, name)
        grade = result.grade
        elapsed = result.elapsed

        grade_colors = {"A": "green", "B": "yellow", "C": "dark_orange", "F": "red", "?": "dim"}
        gc = grade_colors.get(grade, "white")
        icon = _STATUS_ICON.get(result.status, "\u2705")

        bar_done = int(done_count[0] / total * 20)
        bar = f"[blue]{'█' * bar_done}[/blue][dim]{'░' * (20 - bar_done)}[/dim]"

        console.print(
            f"  {icon} [bold]{label:.<20}[/] [{gc}]{grade}[/{gc}]  "
            f"[dim]{elapsed:.1f}s[/dim]  {bar} {done_count[0]}/{total}"
        )

    return callback


# ═══════════════════════════════════════════════════════════════════
#  Main audit
# ═══════════════════════════════════════════════════════════════════


def audit(
    domain: str,
    only: list[str] | None = None,
    max_workers: int = 8,
    show: bool = True,
    deep_subdomains: bool = False,
    progress: bool | None = None,
    tech_patterns: dict | None = None,
) -> AuditResult:
    """Run domain audit.

    Args:
        progress: Show live progress during scanning.
                  None (default) = auto-detect (True in Colab, follows *show* in terminal).
                  True = always show progress. False = never.
    """
    start = time.time()

    # Select scanners
    scanner_map = {k: v for k, v in SCANNERS.items() if k in only} if only else SCANNERS

    scanner_names = list(scanner_map.keys())
    results: dict[str, ScanResult] = {}

    # Set up progress callback
    # Default: always show in Colab (even with show=False), follow `show` in terminal
    show_progress = progress if progress is not None else (is_colab() or show)
    progress_cb: Callable[[str, ScanResult | None], None] | None = None
    if show_progress:
        if is_colab():
            progress_cb = make_progress_colab(domain, scanner_names, _MODULE_LABELS, _STATUS_ICON)
        else:
            progress_cb = _make_progress_terminal(domain, scanner_names)

    # Phase 1: Run subdomain scanner first (if selected) so port scanner can use results
    discovered_subdomains: list[str] = []
    if "subdomains" in scanner_map:
        if progress_cb:
            progress_cb("subdomains", None)
        try:
            sub_result = scanner_map["subdomains"](domain, deep=deep_subdomains)  # type: ignore[call-arg, operator]
            results["subdomains"] = sub_result
            discovered_subdomains = sub_result.raw_data.get("all_subdomains", [])
        except Exception as exc:
            results["subdomains"] = ScanResult(
                module="subdomains",
                status="error",
                grade="?",
                findings=[
                    {
                        "label": "subdomains scanner",
                        "value": f"Unexpected error: {safe_error(exc)}",
                        "grade": "?",
                        "detail": safe_error(exc),
                        "fix": "",
                    }
                ],
                raw_data={"error": safe_error(exc)},
            )
        if progress_cb:
            progress_cb("subdomains", results["subdomains"])

    # Phase 2: Run remaining scanners in parallel
    remaining = {k: v for k, v in scanner_map.items() if k != "subdomains"}

    def _make_scanner_call(name: str, scan_func: Callable, domain: str) -> tuple[str, ScanResult]:
        if progress_cb:
            progress_cb(name, None)  # Signal: scanner starting
        if name == "ports":
            result = scan_func(domain, subdomains=discovered_subdomains)
        elif name == "tech" and tech_patterns:
            result = scan_func(domain, custom_patterns=tech_patterns)
        else:
            result = scan_func(domain)
        return name, result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_name = {
            executor.submit(_make_scanner_call, name, scan_func, domain): name  # type: ignore[arg-type]
            for name, scan_func in remaining.items()
        }

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                _, result = future.result()
                results[name] = result
                if progress_cb:
                    progress_cb(name, result)
            except Exception as exc:
                err_result = ScanResult(
                    module=name,
                    status="error",
                    grade="?",
                    findings=[
                        {
                            "label": f"{name} scanner",
                            "value": f"Unexpected error: {safe_error(exc)}",
                            "grade": "?",
                            "detail": safe_error(exc),
                            "fix": "",
                        }
                    ],
                    raw_data={"error": safe_error(exc)},
                )
                results[name] = err_result
                if progress_cb:
                    progress_cb(name, err_result)

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

    # Show final summary line
    if show:
        if is_colab():
            pass  # Colab progress widget already shows completion
        else:
            from rich.console import Console

            console = Console()
            gc = {"A": "green", "B": "yellow", "C": "dark_orange", "F": "red"}.get(overall_grade, "white")
            console.print()
            console.print(f"  [bold]Overall: [{gc}]{overall_grade}[/{gc}][/]  [dim]{elapsed:.1f}s[/dim]")
            console.print()

    return audit_result
