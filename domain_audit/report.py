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

GRADE_COLORS_HTML = {
    "A": "#22c55e",
    "B": "#eab308",
    "C": "#f97316",
    "F": "#ef4444",
    "?": "#6b7280",
    "-": "#6b7280",
}

SEVERITY_COLORS_HTML = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#6b7280",
}


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
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    console = Console()

    # Header
    grade_color = GRADE_COLORS.get(result.overall_grade, "white")
    title = Text()
    title.append(f"DOMAIN AUDIT: {result.domain}", style="bold")
    title.append("  ")
    title.append(f"Grade: {result.overall_grade}", style=f"bold {grade_color}")

    # Module table
    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Module", style="cyan", min_width=20)
    table.add_column("Grade", justify="center", min_width=7)
    table.add_column("Status", min_width=8)
    table.add_column("Summary", min_width=40)

    module_order = ["ssl", "dns", "subdomains", "headers", "whois", "email", "ports", "tech"]
    module_labels = {
        "ssl": "SSL/TLS",
        "dns": "DNS Records",
        "subdomains": "Subdomains",
        "headers": "HTTP Headers",
        "whois": "WHOIS",
        "email": "Email Security",
        "ports": "Open Ports",
        "tech": "Tech Stack",
    }

    for mod in module_order:
        if mod not in result.results:
            continue
        r = result.results[mod]
        color = GRADE_COLORS.get(r.grade, "white")
        summary = r.findings[0]["detail"] if r.findings else ""
        table.add_row(
            module_labels.get(mod, mod),
            Text(r.grade, style=f"bold {color}"),
            r.status,
            summary,
        )

    console.print()
    console.print(table)

    # Action items
    if result.action_items:
        console.print()
        console.print("[bold]ACTION ITEMS:[/bold]")
        for i, item in enumerate(result.action_items, 1):
            sev = item["severity"]
            sev_color = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "dim"}.get(sev, "white")
            console.print(f"  {i}. [{sev_color}][{sev}][/{sev_color}] {item['issue']}")
            if item.get("fix"):
                console.print(f"     Fix: {item['fix']}", style="dim")

    console.print(f"\n[dim]Completed in {result.elapsed:.1f}s[/dim]")


def _display_colab(result: AuditResult) -> None:
    from IPython.display import display as ipy_display, HTML

    module_labels = {
        "ssl": "SSL/TLS",
        "dns": "DNS Records",
        "subdomains": "Subdomains",
        "headers": "HTTP Headers",
        "whois": "WHOIS",
        "email": "Email Security",
        "ports": "Open Ports",
        "tech": "Tech Stack",
    }
    module_order = ["ssl", "dns", "subdomains", "headers", "whois", "email", "ports", "tech"]

    grade_color = GRADE_COLORS_HTML.get(result.overall_grade, "#6b7280")

    rows = ""
    for mod in module_order:
        if mod not in result.results:
            continue
        r = result.results[mod]
        color = GRADE_COLORS_HTML.get(r.grade, "#6b7280")
        summary = r.findings[0]["detail"] if r.findings else ""

        # Build detail rows for expandable section
        details_html = ""
        for finding in r.findings:
            f_color = GRADE_COLORS_HTML.get(finding.get("grade", "-"), "#6b7280")
            details_html += f"""
            <tr style="background:#1e1e2e;">
                <td style="padding:4px 12px;color:#ccc;font-size:13px;">{finding.get('label','')}</td>
                <td style="padding:4px 12px;color:{f_color};font-weight:bold;font-size:13px;">{finding.get('grade','-')}</td>
                <td style="padding:4px 12px;color:#ccc;font-size:13px;">{finding.get('detail','')}</td>
            </tr>"""
            if finding.get("fix"):
                details_html += f"""
                <tr style="background:#1e1e2e;">
                    <td colspan="3" style="padding:2px 12px 8px 24px;color:#888;font-size:12px;">Fix: {finding['fix']}</td>
                </tr>"""

        rows += f"""
        <tr style="cursor:pointer;" onclick="var d=this.nextElementSibling;d.style.display=d.style.display==='none'?'':'none';">
            <td style="padding:8px 12px;font-weight:bold;">{module_labels.get(mod, mod)}</td>
            <td style="padding:8px 12px;color:{color};font-weight:bold;font-size:18px;text-align:center;">{r.grade}</td>
            <td style="padding:8px 12px;">{r.status}</td>
            <td style="padding:8px 12px;">{summary}</td>
        </tr>
        <tr style="display:none;">
            <td colspan="4" style="padding:0;">
                <table style="width:100%;border-collapse:collapse;">{details_html}</table>
            </td>
        </tr>"""

    # Action items
    action_html = ""
    if result.action_items:
        action_html = '<div style="margin-top:16px;padding:12px;background:#1a1a2e;border-radius:8px;">'
        action_html += '<div style="font-weight:bold;margin-bottom:8px;color:#fff;">ACTION ITEMS</div>'
        for i, item in enumerate(result.action_items, 1):
            sev_color = SEVERITY_COLORS_HTML.get(item["severity"], "#6b7280")
            action_html += f'<div style="margin:4px 0;"><span style="color:{sev_color};font-weight:bold;">[{item["severity"]}]</span> {item["issue"]}'
            if item.get("fix"):
                action_html += f'<br><span style="color:#888;font-size:12px;margin-left:16px;">Fix: {item["fix"]}</span>'
            action_html += "</div>"
        action_html += "</div>"

    html = f"""
    <div style="font-family:monospace;background:#0d1117;color:#e6edf3;padding:20px;border-radius:12px;max-width:800px;">
        <div style="text-align:center;margin-bottom:16px;">
            <div style="font-size:14px;color:#888;">DOMAIN AUDIT</div>
            <div style="font-size:24px;font-weight:bold;">{result.domain}</div>
            <div style="font-size:48px;font-weight:bold;color:{grade_color};margin:8px 0;">{result.overall_grade}</div>
            <div style="font-size:12px;color:#666;">Completed in {result.elapsed:.1f}s</div>
        </div>
        <table style="width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;">
            <tr style="border-bottom:1px solid #30363d;">
                <th style="padding:8px 12px;text-align:left;">Module</th>
                <th style="padding:8px 12px;text-align:center;">Grade</th>
                <th style="padding:8px 12px;text-align:left;">Status</th>
                <th style="padding:8px 12px;text-align:left;">Summary</th>
            </tr>
            {rows}
        </table>
        {action_html}
        <div style="text-align:center;margin-top:12px;font-size:11px;color:#444;">Click any row to expand details</div>
    </div>
    """
    ipy_display(HTML(html))
