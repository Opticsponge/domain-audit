from __future__ import annotations

import html as html_mod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from domain_audit.core import AuditResult


def _esc(text: str) -> str:
    """HTML-escape user-controlled strings to prevent XSS."""
    return html_mod.escape(str(text)) if text else ""


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

MODULE_ORDER = ["subdomains", "ssl", "dns", "headers", "whois", "email", "ports", "tech"]


def display(result: AuditResult) -> None:
    from domain_audit.colab import is_colab

    if is_colab():
        from domain_audit.colab import display_colab

        display_colab(result)
    else:
        _display_terminal(result)


# ═══════════════════════════════════════════════════════════════════
#  TERMINAL (Rich)
# ═══════════════════════════════════════════════════════════════════


def _display_terminal(result: AuditResult) -> None:
    from rich.console import Console

    console = Console()
    domain = result.domain
    grade = result.overall_grade
    gc = GRADE_COLORS.get(grade, "white")

    # ── Header ──
    console.print()
    console.print("  [bold white on blue]  DOMAIN AUDIT  [/]")
    console.print()
    console.print(f"  [bold]{domain}[/bold]  [bold {gc}]{grade}[/bold {gc}]  [dim]{result.elapsed:.1f}s[/dim]")
    console.print()

    # Map check types to subdomain table findings for consolidation
    sub_tables = {}  # e.g. {"ssl": [...], "dns": [...], "http": [...]}
    if "subdomains" in result.results:
        for f in result.results["subdomains"].findings:
            tt = f.get("table_type")
            if tt:
                sub_tables[tt] = f

    # Module -> which subdomain table to append
    MODULE_TO_TABLE = {"ssl": "ssl", "dns": "dns", "headers": "http"}

    # ── Per-module sections ──
    for mod in MODULE_ORDER:
        if mod not in result.results:
            continue
        # Skip subdomains as standalone — its tables are merged into other modules
        if mod == "subdomains":
            # Show discovery summary + the actual subdomain list
            r = result.results[mod]
            non_table = [f for f in r.findings if not f.get("table_type")]
            if non_table:
                color = GRADE_COLORS.get(r.grade, "white")
                label = MODULE_LABELS.get(mod, mod)
                console.print(
                    f"  [bold {color}]{r.grade}[/bold {color}]  [bold]{domain}[/bold] [dim]>[/dim] [bold]{label}[/bold]"
                )
                console.print(f"  [dim]{'─' * 60}[/dim]")
                for f in non_table:
                    console.print(f"     [dim]{f.get('detail', '')}[/dim]")
                    sub_list = f.get("subdomain_list", [])
                    if sub_list:
                        # Show in columns
                        from rich.columns import Columns

                        styled = [f"[cyan]{s}[/cyan]" for s in sub_list]
                        console.print(Columns(styled, padding=(0, 2), column_first=True))
                console.print()
            continue

        r = result.results[mod]
        color = GRADE_COLORS.get(r.grade, "white")
        label = MODULE_LABELS.get(mod, mod)

        # Module header: always includes domain
        console.print(
            f"  [bold {color}]{r.grade}[/bold {color}]  [bold]{domain}[/bold] [dim]>[/dim] [bold]{label}[/bold]"
        )
        console.print(f"  [dim]{'─' * 60}[/dim]")

        # Check if findings have detailed record/test data (email security style)
        has_detail_tables = any(f.get("tests") for f in r.findings)

        if has_detail_tables:
            _display_terminal_detailed_findings(console, r.findings, domain, label)
        else:
            _display_terminal_simple_findings(console, r.findings)

        # Append matching subdomain table under this module
        table_key = MODULE_TO_TABLE.get(mod)
        if table_key and table_key in sub_tables:
            sub_finding = sub_tables[table_key]
            console.print("     [bold]Subdomains[/bold]")
            _display_terminal_simple_findings(console, [sub_finding])

        console.print()

    # ── Action Items ──
    if result.action_items:
        console.print(
            f"  [bold white on red]  ACTION ITEMS  [/]  [bold]{domain}[/bold]  [dim]{len(result.action_items)} issue(s)[/dim]"
        )
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


def _display_terminal_simple_findings(console, findings: list) -> None:
    """Standard findings display — collapse passing, highlight problems. Renders subdomain tables."""
    from rich.table import Table

    good = []
    bad = []
    table_findings = []
    for f in findings:
        if f.get("table_type"):
            table_findings.append(f)
        elif f.get("grade", "-") in ("A", "-"):
            good.append(f)
        else:
            bad.append(f)

    for f in bad:
        fg = f.get("grade", "?")
        fc = GRADE_COLORS.get(fg, "dim")
        console.print(f"     [{fc}][{fg}][/{fc}]  {f.get('detail', '')}")
        fix = f.get("fix", "")
        if fix:
            console.print(f"         [cyan]Fix:[/cyan] {fix}")

    if good and not bad and not table_findings:
        if len(good) <= 2:
            for f in good:
                console.print(f"     [green]A[/green]  [dim]{f.get('detail', '')}[/dim]")
        else:
            console.print(f"     [green]A[/green]  [dim]{good[0].get('detail', '')}[/dim]")
            console.print(f"         [dim]+ {len(good) - 1} more checks passed[/dim]")
    elif good and (bad or table_findings):
        for f in good:
            console.print(f"     [dim]{f.get('detail', '')}[/dim]")

    # Render subdomain data tables
    for f in table_findings:
        table_type = f["table_type"]
        table_data = f.get("table_data", [])
        if not table_data:
            continue

        fg = f.get("grade", "-")
        fc = GRADE_COLORS.get(fg, "dim")
        console.print()
        console.print(f"     [{fc}]{fg}[/{fc}]  [bold]{f.get('label', '')}[/bold]  [dim]{f.get('detail', '')}[/dim]")

        if table_type == "dns":
            t = Table(show_header=True, header_style="bold", padding=(0, 1), box=None, pad_edge=False)
            t.add_column("Subdomain", style="cyan", min_width=30)
            t.add_column("A Record(s)", min_width=16)
            t.add_column("AAAA", min_width=8)
            t.add_column("CNAME", min_width=16)
            for row in table_data:
                t.add_row(row["subdomain"], row["a_records"], row["aaaa_records"], row["cname"])
            console.print(t)

        elif table_type == "ssl":
            t = Table(show_header=True, header_style="bold", padding=(0, 1), box=None, pad_edge=False)
            t.add_column("Subdomain", style="cyan", min_width=28)
            t.add_column("IP", min_width=14)
            t.add_column("Valid", min_width=6)
            t.add_column("Issuer", min_width=14)
            t.add_column("Days Left", justify="right", min_width=9)
            t.add_column("Protocol", min_width=8)
            t.add_column("Grade", min_width=5)
            for row in table_data:
                gc = GRADE_COLORS.get(row["grade"], "dim")
                t.add_row(
                    row["subdomain"],
                    row["ip"],
                    row["valid"],
                    row["issuer"],
                    row["days_left"],
                    row["protocol"],
                    f"[{gc}]{row['grade']}[/{gc}]",
                )
            console.print(t)

        elif table_type == "http":
            t = Table(show_header=True, header_style="bold", padding=(0, 1), box=None, pad_edge=False)
            t.add_column("Subdomain", style="cyan", min_width=28)
            t.add_column("Reachable", min_width=9)
            t.add_column("HTTPS", min_width=6)
            t.add_column("Status", min_width=6)
            t.add_column("Server", min_width=12)
            t.add_column("Time", justify="right", min_width=7)
            t.add_column("Redirect", min_width=20)
            for row in table_data:
                https_style = "green" if row["https"] == "Yes" else "red" if row["reachable"] == "Yes" else "dim"
                ms = row.get("response_ms", "-")
                t.add_row(
                    row["subdomain"],
                    row["reachable"],
                    f"[{https_style}]{row['https']}[/{https_style}]",
                    row["status"],
                    row["server"],
                    ms,
                    row["redirect"],
                )
            console.print(t)

        fix = f.get("fix", "")
        if fix:
            console.print(f"         [cyan]Fix:[/cyan] {fix}")


def _display_terminal_detailed_findings(console, findings: list, domain: str, module_label: str) -> None:
    """MXToolbox-style display with parsed record tables + validation tests."""
    from rich.table import Table

    for f in findings:
        rec_type = f.get("record_type", f.get("label", ""))
        fg = f.get("grade", "-")
        fc = GRADE_COLORS.get(fg, "dim")
        raw_value = f.get("value", "")

        # Sub-header
        console.print(f"     [bold]{rec_type}[/bold]  [{fc}]{fg}[/{fc}]  [dim]{domain}[/dim]")

        # Raw record
        if raw_value and raw_value != "Not found":
            console.print(f"     [dim]Record:[/dim] {raw_value}")

        # Parsed record table
        parsed = f.get("parsed_record", [])
        if parsed:
            console.print()
            table = Table(show_header=True, header_style="bold", padding=(0, 1), box=None, pad_edge=False)
            table.add_column("Tag", style="cyan", min_width=8)
            table.add_column("Value", min_width=20)
            table.add_column("Name", style="bold", min_width=12)
            table.add_column("Description", style="dim", max_width=50)
            for row in parsed:
                table.add_row(row["tag"], row["value"], row["name"], row["description"])
            console.print(table)

        # Validation tests table
        tests = f.get("tests", [])
        if tests:
            console.print()
            test_table = Table(show_header=True, header_style="bold", padding=(0, 1), box=None, pad_edge=False)
            test_table.add_column("", min_width=3)
            test_table.add_column("Test", style="bold", min_width=24)
            test_table.add_column("Result", min_width=40)
            for t in tests:
                icon = "[green]✓[/green]" if t["pass"] else "[red]✗[/red]"
                test_table.add_row(icon, t["test"], t["result"])
            console.print(test_table)

        # Fix suggestion
        fix = f.get("fix", "")
        if fix:
            console.print(f"     [cyan]Fix:[/cyan] {fix}")

        console.print()
