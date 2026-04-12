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

GRADE_LABEL_HTML = {
    "A": "PASS",
    "B": "OK",
    "C": "WARN",
    "F": "FAIL",
    "?": "ERROR",
    "-": "INFO",
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


# ═══════════════════════════════════════════════════════════════════
#  TERMINAL (Rich)
# ═══════════════════════════════════════════════════════════════════

def _display_terminal(result: AuditResult) -> None:
    from rich.console import Console
    from rich.text import Text

    console = Console()
    domain = result.domain
    grade = result.overall_grade
    gc = GRADE_COLORS.get(grade, "white")

    # ── Header ──
    console.print()
    console.print(f"  [bold white on blue]  DOMAIN AUDIT  [/]")
    console.print()
    console.print(f"  [bold]{domain}[/bold]  [bold {gc}]{grade}[/bold {gc}]  [dim]{result.elapsed:.1f}s[/dim]")
    console.print()

    # ── Per-module sections ──
    for mod in MODULE_ORDER:
        if mod not in result.results:
            continue
        r = result.results[mod]
        color = GRADE_COLORS.get(r.grade, "white")
        label = MODULE_LABELS.get(mod, mod)

        # Module header: always includes domain
        console.print(f"  [bold {color}]{r.grade}[/bold {color}]  [bold]{domain}[/bold] [dim]>[/dim] [bold]{label}[/bold]")
        console.print(f"  [dim]{'─' * 60}[/dim]")

        # Separate good vs bad findings
        good = []
        bad = []
        for f in r.findings:
            fg = f.get("grade", "-")
            if fg in ("A", "-"):
                good.append(f)
            else:
                bad.append(f)

        # Bad findings: prominent, with fix inline
        for f in bad:
            fg = f.get("grade", "?")
            fc = GRADE_COLORS.get(fg, "dim")
            console.print(f"     [{fc}][{fg}][/{fc}]  {f.get('detail', '')}")
            fix = f.get("fix", "")
            if fix:
                console.print(f"         [cyan]Fix:[/cyan] {fix}")

        # Good findings: compact
        if good and not bad:
            if len(good) <= 2:
                for f in good:
                    console.print(f"     [green]A[/green]  [dim]{f.get('detail', '')}[/dim]")
            else:
                console.print(f"     [green]A[/green]  [dim]{good[0].get('detail', '')}[/dim]")
                console.print(f"         [dim]+ {len(good) - 1} more checks passed[/dim]")
        elif good and bad:
            console.print(f"         [dim]{len(good)} other check(s) passed[/dim]")

        console.print()

    # ── Action Items ──
    if result.action_items:
        console.print(f"  [bold white on red]  ACTION ITEMS  [/]  [bold]{domain}[/bold]  [dim]{len(result.action_items)} issue(s)[/dim]")
        console.print(f"  [dim]{'─' * 60}[/dim]")
        console.print()

        for i, item in enumerate(result.action_items, 1):
            sev = item["severity"]
            ss = SEVERITY_COLORS.get(sev, "dim")
            mod_label = MODULE_LABELS.get(item.get("module", ""), item.get("module", ""))

            console.print(f"  {i:>2}.  [{ss}]{sev}[/{ss}]")
            console.print(f"       [bold]{item['issue']}[/bold]")
            console.print(f"       [dim]{domain} > {mod_label}[/dim]")
            if item.get("fix"):
                console.print(f"       [cyan]Fix:[/cyan] {item['fix']}")
            console.print()
    else:
        console.print(f"  [bold green]No issues found for {domain}[/bold green]")
        console.print()


# ═══════════════════════════════════════════════════════════════════
#  COLAB (HTML)
# ═══════════════════════════════════════════════════════════════════

def _display_colab(result: AuditResult) -> None:
    import random
    from IPython.display import display as ipy_display, HTML

    domain = result.domain
    grade_color = GRADE_COLORS_HTML.get(result.overall_grade, "#6b7280")
    # Unique ID so multiple audits on one page don't collide
    uid = f"da{random.randint(10000,99999)}"

    # ── Summary table rows ──
    summary_rows = ""
    for mod in MODULE_ORDER:
        if mod not in result.results:
            continue
        r = result.results[mod]
        color = GRADE_COLORS_HTML.get(r.grade, "#6b7280")
        label = MODULE_LABELS.get(mod, mod)
        status_label = GRADE_LABEL_HTML.get(r.grade, "")

        # One-line summary: first problem finding, or first finding
        summary = ""
        issue_count = 0
        for f in r.findings:
            if f.get("grade", "-") not in ("A", "-"):
                issue_count += 1
        if issue_count > 0:
            summary = f'<span style="color:{color};">{issue_count} issue(s)</span>'
        else:
            summary = f'<span style="color:#8b949e;">{r.findings[0].get("detail", "") if r.findings else "OK"}</span>'

        summary_rows += f"""
        <tr style="cursor:pointer;border-bottom:1px solid #21262d;" onclick="var d=document.getElementById('{uid}_{mod}');d.style.display=d.style.display==='none'?'block':'none';">
            <td style="padding:10px 14px;">
                <span style="color:{color};font-weight:bold;font-size:18px;display:inline-block;width:28px;text-align:center;">{r.grade}</span>
            </td>
            <td style="padding:10px 8px;">
                <span style="color:{color};font-size:10px;text-transform:uppercase;letter-spacing:1px;padding:2px 6px;background:{color}15;border-radius:3px;">{status_label}</span>
            </td>
            <td style="padding:10px 8px;font-weight:bold;">{domain} &rsaquo; {label}</td>
            <td style="padding:10px 8px;font-size:13px;">{summary}</td>
            <td style="padding:10px 8px;color:#484f58;font-size:16px;text-align:center;">&#9662;</td>
        </tr>"""

    # ── Expandable detail panels (hidden by default) ──
    detail_panels = ""
    for mod in MODULE_ORDER:
        if mod not in result.results:
            continue
        r = result.results[mod]
        color = GRADE_COLORS_HTML.get(r.grade, "#6b7280")
        label = MODULE_LABELS.get(mod, mod)

        findings_html = ""
        for f in r.findings:
            fg = f.get("grade", "-")
            fc = GRADE_COLORS_HTML.get(fg, "#6b7280")
            detail = f.get("detail", "")
            fix = f.get("fix", "")

            if fg in ("A", "-"):
                findings_html += f"""
                <div style="padding:6px 14px;color:#8b949e;font-size:13px;display:flex;align-items:baseline;gap:8px;">
                    <span style="color:{fc};font-size:11px;">&#10003;</span>
                    <span>{detail}</span>
                </div>"""
            else:
                findings_html += f"""
                <div style="padding:8px 14px;margin:4px 8px;background:#161b22;border-left:3px solid {fc};border-radius:0 6px 6px 0;">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span style="color:{fc};font-weight:bold;font-size:12px;">{fg}</span>
                        <span style="color:#e6edf3;font-size:13px;">{detail}</span>
                    </div>
                    <div style="color:#8b949e;font-size:11px;margin-top:3px;margin-left:24px;">{domain} &rsaquo; {label}</div>
                    {"<div style='color:#58a6ff;font-size:12px;margin-top:4px;margin-left:24px;'>Fix: " + fix + "</div>" if fix else ""}
                </div>"""

        detail_panels += f"""
        <div id="{uid}_{mod}" style="display:none;background:#0d1117;border:1px solid #21262d;border-top:none;margin:-1px 0 12px 0;border-radius:0 0 8px 8px;padding:10px 4px;">
            <div style="padding:4px 14px 8px;color:#8b949e;font-size:11px;border-bottom:1px solid #21262d;margin-bottom:6px;">
                {domain} &rsaquo; {label} &mdash; Detail
            </div>
            {findings_html}
        </div>"""

    # ── Action items ──
    action_html = ""
    if result.action_items:
        items_html = ""
        for i, item in enumerate(result.action_items, 1):
            sev = item["severity"]
            sev_color = SEVERITY_COLORS_HTML.get(sev, "#6b7280")
            mod_label = MODULE_LABELS.get(item.get("module", ""), item.get("module", ""))
            fix = item.get("fix", "")

            items_html += f"""
            <div style="margin:6px 0;padding:10px 12px;background:#0d1117;border:1px solid #21262d;border-left:3px solid {sev_color};border-radius:0 6px 6px 0;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
                    <span style="color:{sev_color};font-weight:bold;font-size:10px;text-transform:uppercase;letter-spacing:1px;padding:2px 6px;background:{sev_color}18;border-radius:3px;">{sev}</span>
                    <span style="font-weight:bold;font-size:13px;">{item['issue']}</span>
                </div>
                <div style="color:#8b949e;font-size:12px;margin-left:4px;">{domain} &rsaquo; {mod_label}</div>
                {"<div style='color:#58a6ff;font-size:12px;margin-top:4px;margin-left:4px;'>Fix: " + fix + "</div>" if fix else ""}
            </div>"""

        action_html = f"""
        <div style="margin-top:20px;">
            <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:#2d1215;border-radius:8px 8px 0 0;border-bottom:2px solid #ef4444;">
                <span style="font-size:16px;">&#9888;</span>
                <div style="flex:1;">
                    <span style="font-weight:bold;font-size:14px;">Action Items for {domain}</span>
                    <span style="font-size:11px;color:#f87171;margin-left:8px;">{len(result.action_items)} issue(s)</span>
                </div>
            </div>
            <div style="background:#161b22;border:1px solid #21262d;border-top:none;border-radius:0 0 8px 8px;padding:8px;">
                {items_html}
            </div>
        </div>"""

    # ── JavaScript for expand/collapse ──
    js = f"""
    <script>
    function {uid}_toggleAll() {{
        var panels = [{', '.join(f"'{uid}_{mod}'" for mod in MODULE_ORDER if mod in result.results)}];
        var btn = document.getElementById('{uid}_toggleBtn');
        var expanding = btn.innerText.indexOf('Expand') !== -1;
        panels.forEach(function(id) {{
            var el = document.getElementById(id);
            if (el) el.style.display = expanding ? 'block' : 'none';
        }});
        btn.innerText = expanding ? '▲ Collapse All' : '▼ Expand All';
    }}
    </script>
    """

    html = f"""
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#010409;color:#e6edf3;padding:24px;border-radius:12px;max-width:780px;">
        <div style="text-align:center;margin-bottom:24px;">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:3px;color:#6b7280;">Domain Audit Report</div>
            <div style="font-size:32px;font-weight:bold;margin:8px 0;color:#fff;">{domain}</div>
            <div style="display:inline-block;padding:10px 32px;border-radius:10px;background:{grade_color}15;border:2px solid {grade_color}40;margin-top:8px;">
                <div style="font-size:48px;font-weight:bold;color:{grade_color};">{result.overall_grade}</div>
                <div style="font-size:11px;color:{grade_color};text-transform:uppercase;letter-spacing:2px;">Overall</div>
            </div>
            <div style="font-size:12px;color:#484f58;margin-top:12px;">Scanned in {result.elapsed:.1f}s &bull; {len(result.results)} modules &bull; {len(result.action_items)} issue(s)</div>
        </div>

        <!-- Summary Table -->
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
            <span style="font-weight:bold;font-size:14px;">Scan Results</span>
            <span id="{uid}_toggleBtn" onclick="{uid}_toggleAll()" style="cursor:pointer;color:#58a6ff;font-size:12px;padding:4px 10px;border:1px solid #21262d;border-radius:6px;background:#161b22;">&#9660; Expand All</span>
        </div>
        <table style="width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;">
            <thead>
                <tr style="border-bottom:2px solid #30363d;">
                    <th style="padding:8px 14px;text-align:left;font-size:12px;color:#8b949e;width:36px;">Grade</th>
                    <th style="padding:8px 8px;text-align:left;font-size:12px;color:#8b949e;width:50px;">Status</th>
                    <th style="padding:8px 8px;text-align:left;font-size:12px;color:#8b949e;">Module</th>
                    <th style="padding:8px 8px;text-align:left;font-size:12px;color:#8b949e;">Summary</th>
                    <th style="width:30px;"></th>
                </tr>
            </thead>
            <tbody>
                {summary_rows}
            </tbody>
        </table>

        <!-- Expandable Detail Panels -->
        {detail_panels}

        <div style="text-align:center;margin-top:4px;font-size:11px;color:#30363d;">Click a row to expand &bull; Click again to collapse</div>

        <!-- Action Items -->
        {action_html}
    </div>
    {js}
    """
    ipy_display(HTML(html))
