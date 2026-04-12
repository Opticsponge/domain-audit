from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from domain_audit.core import AuditResult

GRADE_COLORS = {
    "A": "green",
    "B": "yellow",
    "C": "dark_orange",
    "F": "red",
    "?": "dim",
    "-": "dim",
}

GRADE_EMOJI = {
    "A": "[green]PASS[/green]",
    "B": "[yellow]OK[/yellow]  ",
    "C": "[dark_orange]WARN[/dark_orange]",
    "F": "[red]FAIL[/red]",
    "?": "[dim]ERR [/dim]",
    "-": "[dim]INFO[/dim]",
}

GRADE_COLORS_HTML = {
    "A": "#22c55e",
    "B": "#eab308",
    "C": "#f97316",
    "F": "#ef4444",
    "?": "#6b7280",
    "-": "#6b7280",
}

SEVERITY_COLORS = {
    "CRITICAL": "red bold",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "dim",
}

SEVERITY_COLORS_HTML = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#6b7280",
}

MODULE_LABELS = {
    "ssl": "SSL/TLS",
    "dns": "DNS Records",
    "subdomains": "Subdomains",
    "headers": "HTTP Headers",
    "whois": "WHOIS",
    "email": "Email Security",
    "ports": "Open Ports",
    "tech": "Tech Stack",
}

MODULE_ORDER = ["ssl", "dns", "subdomains", "headers", "whois", "email", "ports", "tech"]


def _is_colab() -> bool:
    try:
        from google.colab import output  # noqa: F401
        return True
    except ImportError:
        return False


def display(result: AuditResult) -> None:
    if _is_colab():
        _display_colab(result)
    else:
        _display_terminal(result)


def _display_terminal(result: AuditResult) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich import box

    console = Console()
    domain = result.domain
    grade = result.overall_grade
    grade_color = GRADE_COLORS.get(grade, "white")

    # ── Header ──
    console.print()
    header = Text()
    header.append("  DOMAIN AUDIT  ", style="bold white on blue")
    console.print(header)
    console.print()
    console.print(f"  Domain:  [bold]{domain}[/bold]")
    console.print(f"  Grade:   [bold {grade_color}]{grade}[/bold {grade_color}]")
    console.print(f"  Time:    [dim]{result.elapsed:.1f}s[/dim]")

    # ── Module Results ──
    console.print()
    console.print("  [bold]SCAN RESULTS[/bold]")
    console.print("  [dim]" + "─" * 68 + "[/dim]")

    for mod in MODULE_ORDER:
        if mod not in result.results:
            continue
        r = result.results[mod]
        color = GRADE_COLORS.get(r.grade, "white")
        label = MODULE_LABELS.get(mod, mod)
        status_tag = GRADE_EMOJI.get(r.grade, "[dim]???[/dim]")

        # Module header line
        console.print(f"  {status_tag}  [bold {color}]{r.grade}[/bold {color}]  [bold]{label}[/bold]")

        # Show findings: collapse passing checks, highlight problems
        good_findings = []
        bad_findings = []
        for finding in r.findings:
            f_grade = finding.get("grade", "-")
            detail = finding.get("detail", "")
            if f_grade in ("A", "-"):
                good_findings.append(detail)
            else:
                bad_findings.append((f_grade, detail))

        # Problems first, prominently
        for f_grade, detail in bad_findings:
            f_color = GRADE_COLORS.get(f_grade, "dim")
            console.print(f"        [{f_color}][{f_grade}] {detail}[/{f_color}]")

        # Good findings collapsed into one line if module is passing
        if good_findings and not bad_findings:
            # All good — show a compact summary
            if len(good_findings) <= 2:
                for detail in good_findings:
                    console.print(f"        [dim]{detail}[/dim]")
            else:
                console.print(f"        [dim]{good_findings[0]}[/dim]")
                console.print(f"        [dim]+ {len(good_findings) - 1} more checks passed[/dim]")
        elif good_findings and bad_findings:
            # Mixed — just note how many passed
            console.print(f"        [dim]{len(good_findings)} other check(s) passed[/dim]")

        console.print()

    # ── Action Items ──
    if result.action_items:
        console.print("  [bold]ACTION ITEMS FOR [/bold][bold cyan]{domain}[/bold cyan]".format(domain=domain))
        console.print("  [dim]" + "─" * 68 + "[/dim]")

        for i, item in enumerate(result.action_items, 1):
            sev = item["severity"]
            sev_style = SEVERITY_COLORS.get(sev, "dim")
            module_label = MODULE_LABELS.get(item.get("module", ""), item.get("module", ""))

            console.print(
                f"  [{sev_style}]{sev:8s}[/{sev_style}]  "
                f"[bold]{item['issue']}[/bold]"
            )
            console.print(
                f"  {'':8s}  [dim]{domain} > {module_label}[/dim]"
            )
            if item.get("fix"):
                console.print(
                    f"  {'':8s}  [cyan]Fix:[/cyan] {item['fix']}"
                )
            console.print()

    else:
        console.print(f"  [green bold]No issues found for {domain}[/green bold]")
        console.print()


def _display_colab(result: AuditResult) -> None:
    from IPython.display import display as ipy_display, HTML

    domain = result.domain
    grade_color = GRADE_COLORS_HTML.get(result.overall_grade, "#6b7280")

    # ── Module rows ──
    module_rows = ""
    for mod in MODULE_ORDER:
        if mod not in result.results:
            continue
        r = result.results[mod]
        color = GRADE_COLORS_HTML.get(r.grade, "#6b7280")
        label = MODULE_LABELS.get(mod, mod)

        # Build finding details
        findings_html = ""
        for finding in r.findings:
            f_grade = finding.get("grade", "-")
            f_color = GRADE_COLORS_HTML.get(f_grade, "#6b7280")
            detail = finding.get("detail", "")
            fix = finding.get("fix", "")

            icon = "&#10003;" if f_grade == "A" else "&#8226;" if f_grade == "-" else "&#10007;"
            findings_html += f"""
                <div style="padding:4px 0 4px 20px;color:#ccc;font-size:13px;border-left:2px solid {f_color}33;margin:2px 0;">
                    <span style="color:{f_color};">{icon}</span> {detail}
                    {"<br><span style='color:#58a6ff;margin-left:18px;font-size:12px;'>Fix: " + fix + "</span>" if fix else ""}
                </div>"""

        module_rows += f"""
        <div style="margin-bottom:12px;padding:12px;background:#161b22;border-radius:8px;border-left:3px solid {color};">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                <span style="color:{color};font-weight:bold;font-size:20px;min-width:24px;">{r.grade}</span>
                <span style="font-weight:bold;font-size:15px;">{label}</span>
            </div>
            {findings_html}
        </div>"""

    # ── Action items ──
    action_html = ""
    if result.action_items:
        action_html = f"""
        <div style="margin-top:20px;">
            <div style="font-weight:bold;font-size:16px;margin-bottom:10px;color:#fff;">
                Action Items for <span style="color:#58a6ff;">{domain}</span>
            </div>"""

        for i, item in enumerate(result.action_items, 1):
            sev = item["severity"]
            sev_color = SEVERITY_COLORS_HTML.get(sev, "#6b7280")
            module_label = MODULE_LABELS.get(item.get("module", ""), item.get("module", ""))
            fix = item.get("fix", "")

            action_html += f"""
            <div style="margin:8px 0;padding:10px 12px;background:#161b22;border-radius:6px;border-left:3px solid {sev_color};">
                <div>
                    <span style="color:{sev_color};font-weight:bold;font-size:11px;text-transform:uppercase;letter-spacing:1px;">{sev}</span>
                    <span style="margin-left:8px;font-weight:bold;">{item['issue']}</span>
                </div>
                <div style="color:#666;font-size:12px;margin-top:2px;">{domain} &rsaquo; {module_label}</div>
                {"<div style='color:#58a6ff;font-size:12px;margin-top:4px;'>Fix: " + fix + "</div>" if fix else ""}
            </div>"""

        action_html += "</div>"

    html = f"""
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:24px;border-radius:12px;max-width:720px;">
        <div style="text-align:center;margin-bottom:24px;">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:#666;">Domain Audit</div>
            <div style="font-size:28px;font-weight:bold;margin:4px 0;">{domain}</div>
            <div style="display:inline-block;padding:8px 24px;border-radius:8px;background:{grade_color}22;margin-top:8px;">
                <span style="font-size:42px;font-weight:bold;color:{grade_color};">{result.overall_grade}</span>
            </div>
            <div style="font-size:12px;color:#555;margin-top:8px;">Scanned in {result.elapsed:.1f}s</div>
        </div>
        {module_rows}
        {action_html}
    </div>
    """
    ipy_display(HTML(html))
