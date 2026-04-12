from __future__ import annotations

import io
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

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
    "pass": "\u2705",    # green check
    "warn": "\u26a0\ufe0f",    # warning
    "fail": "\u274c",    # red X
    "error": "\u274c",   # red X
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


# ═══════════════════════════════════════════════════════════════════
#  Progress tracking
# ═══════════════════════════════════════════════════════════════════

def _is_colab() -> bool:
    try:
        from google.colab import output  # noqa: F401
        return True
    except ImportError:
        return False


def _make_progress_colab(domain: str, scanner_names: list[str]) -> Callable[[str, ScanResult | None], None]:
    """Return a callback that updates a live HTML widget in Colab."""
    from IPython.display import display as ipy_display, HTML
    import html as html_mod

    state: dict[str, str] = {name: "pending" for name in scanner_names}
    results_map: dict[str, ScanResult] = {}

    # Create an output handle we can update
    from IPython.display import display as ipy_display
    import IPython.display

    handle = ipy_display(HTML(""), display_id=True)

    def _render() -> str:
        total = len(scanner_names)
        done = sum(1 for v in state.values() if v != "pending" and v != "running")
        pct = int(done / total * 100) if total else 0

        rows = ""
        for name in scanner_names:
            label = html_mod.escape(_MODULE_LABELS.get(name, name))
            s = state[name]
            if s == "pending":
                icon = "\u23f3"  # hourglass
                status_text = '<span style="color:#6b7280">Waiting...</span>'
                grade_badge = ""
            elif s == "running":
                icon = "\u26a1"  # lightning
                status_text = '<span style="color:#3b82f6;font-weight:600">Scanning...</span>'
                grade_badge = ""
            else:
                # Completed — get result details
                r = results_map.get(name)
                if r and r.status == "error":
                    icon = "\u274c"
                    status_text = f'<span style="color:#ef4444">Error ({r.elapsed:.1f}s)</span>'
                    grade_badge = '<span style="background:#ef4444;color:white;padding:1px 8px;border-radius:4px;font-weight:700">?</span>'
                elif r:
                    grade = r.grade
                    elapsed = r.elapsed
                    colors = {"A": "#22c55e", "B": "#eab308", "C": "#f97316", "F": "#ef4444"}
                    gc = colors.get(grade, "#6b7280")
                    icon = _STATUS_ICON.get(r.status, "\u2705")
                    status_text = f'<span style="color:{gc}">Done ({elapsed:.1f}s)</span>'
                    grade_badge = f'<span style="background:{gc};color:white;padding:1px 8px;border-radius:4px;font-weight:700">{html_mod.escape(grade)}</span>'
                else:
                    icon = "\u2705"
                    status_text = '<span style="color:#22c55e">Done</span>'
                    grade_badge = ""

            rows += f"""<tr>
                <td style="padding:4px 12px">{icon}</td>
                <td style="padding:4px 12px;font-weight:600">{label}</td>
                <td style="padding:4px 12px">{status_text}</td>
                <td style="padding:4px 12px;text-align:center">{grade_badge}</td>
            </tr>"""

        bar_color = "#22c55e" if pct == 100 else "#3b82f6"
        return f"""<div style="font-family:system-ui,sans-serif;max-width:500px;margin:8px 0">
            <div style="font-size:14px;font-weight:700;margin-bottom:8px">
                Scanning {html_mod.escape(domain)}... {done}/{total} complete
            </div>
            <div style="background:#e5e7eb;border-radius:6px;height:8px;margin-bottom:12px;overflow:hidden">
                <div style="background:{bar_color};height:100%;width:{pct}%;transition:width 0.3s ease;border-radius:6px"></div>
            </div>
            <table style="border-collapse:collapse;width:100%">{rows}</table>
        </div>"""

    def callback(name: str, result: ScanResult | None) -> None:
        if result is None:
            state[name] = "running"
        else:
            state[name] = "done"
            results_map[name] = result
        handle.update(IPython.display.HTML(_render()))

    # Initial render
    handle.update(IPython.display.HTML(_render()))
    return callback


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
) -> AuditResult:
    """Run domain audit.

    Args:
        progress: Show live progress during scanning.
                  None (default) = auto-detect (True in Colab, follows *show* in terminal).
                  True = always show progress. False = never.
    """
    start = time.time()

    # Select scanners
    if only:
        scanner_map = {k: v for k, v in SCANNERS.items() if k in only}
    else:
        scanner_map = SCANNERS

    scanner_names = list(scanner_map.keys())
    results: dict[str, ScanResult] = {}

    # Set up progress callback
    # Default: always show in Colab (even with show=False), follow `show` in terminal
    show_progress = progress if progress is not None else (_is_colab() or show)
    progress_cb: Callable[[str, ScanResult | None], None] | None = None
    if show_progress:
        if _is_colab():
            progress_cb = _make_progress_colab(domain, scanner_names)
        else:
            progress_cb = _make_progress_terminal(domain, scanner_names)

    # Phase 1: Run subdomain scanner first (if selected) so port scanner can use results
    discovered_subdomains: list[str] = []
    if "subdomains" in scanner_map:
        if progress_cb:
            progress_cb("subdomains", None)
        try:
            sub_result = scanner_map["subdomains"](domain, deep=deep_subdomains)
            results["subdomains"] = sub_result
            discovered_subdomains = sub_result.raw_data.get("all_subdomains", [])
        except Exception as exc:
            results["subdomains"] = ScanResult(
                module="subdomains",
                status="error",
                grade="?",
                findings=[{
                    "label": "subdomains scanner",
                    "value": f"Unexpected error: {safe_error(exc)}",
                    "grade": "?",
                    "detail": safe_error(exc),
                    "fix": "",
                }],
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
        else:
            result = scan_func(domain)
        return name, result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_name = {
            executor.submit(_make_scanner_call, name, scan_func, domain): name
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
                    findings=[{
                        "label": f"{name} scanner",
                        "value": f"Unexpected error: {safe_error(exc)}",
                        "grade": "?",
                        "detail": safe_error(exc),
                        "fix": "",
                    }],
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
        if _is_colab():
            pass  # Colab progress widget already shows completion
        else:
            from rich.console import Console
            console = Console()
            gc = {"A": "green", "B": "yellow", "C": "dark_orange", "F": "red"}.get(overall_grade, "white")
            console.print()
            console.print(f"  [bold]Overall: [{gc}]{overall_grade}[/{gc}][/]  [dim]{elapsed:.1f}s[/dim]")
            console.print()

    return audit_result
