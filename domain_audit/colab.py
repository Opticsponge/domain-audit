"""Google Colab integration — detection, progress widget, and HTML report rendering."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from domain_audit.grader import ScanResult
from domain_audit.report import (
    GRADE_COLORS_HTML,
    GRADE_LABEL_HTML,
    MODULE_LABELS,
    MODULE_ORDER,
    SEVERITY_COLORS_HTML,
    _esc,
)

if TYPE_CHECKING:
    from domain_audit.core import AuditResult


def is_colab() -> bool:
    try:
        from google.colab import output  # noqa: F401

        return True
    except ImportError:
        return False


def make_progress_colab(
    domain: str,
    scanner_names: list[str],
    module_labels: dict[str, str],
    status_icon: dict[str, str],
) -> Callable[[str, ScanResult | None], None]:
    """Return a callback that updates a live HTML widget in Colab."""
    import html as html_mod

    from IPython.display import HTML
    from IPython.display import display as ipy_display

    state: dict[str, str] = {name: "pending" for name in scanner_names}
    results_map: dict[str, ScanResult] = {}

    # Create an output handle we can update
    import IPython.display

    handle = ipy_display(HTML(""), display_id=True)

    def _render() -> str:
        total = len(scanner_names)
        done = sum(1 for v in state.values() if v != "pending" and v != "running")
        pct = int(done / total * 100) if total else 0

        rows = ""
        for name in scanner_names:
            label = html_mod.escape(module_labels.get(name, name))
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
                    icon = status_icon.get(r.status, "\u2705")
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


def colab_data_table(table_type: str, table_data: list[dict]) -> str:
    """Generate HTML table for subdomain data (DNS, SSL, HTTP)."""
    ths = "padding:6px 8px;text-align:left;color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;"
    tds = "padding:5px 8px;font-size:12px;border-bottom:1px solid #21262d;"

    if table_type == "dns":
        html = f"""<table style="width:100%;border-collapse:collapse;">
            <tr style="border-bottom:1px solid #30363d;">
                <th style="{ths}">Subdomain</th>
                <th style="{ths}">A Record(s)</th>
                <th style="{ths}">AAAA</th>
                <th style="{ths}">CNAME</th>
            </tr>"""
        for row in table_data:
            html += f"""<tr>
                <td style="{tds}color:#58a6ff;font-family:monospace;">{_esc(row["subdomain"])}</td>
                <td style="{tds}font-family:monospace;">{row["a_records"]}</td>
                <td style="{tds}font-family:monospace;">{row["aaaa_records"]}</td>
                <td style="{tds}font-family:monospace;">{row["cname"]}</td>
            </tr>"""
        html += "</table>"
        return html

    elif table_type == "ssl":
        html = f"""<table style="width:100%;border-collapse:collapse;">
            <tr style="border-bottom:1px solid #30363d;">
                <th style="{ths}">Subdomain</th>
                <th style="{ths}">IP</th>
                <th style="{ths}">Valid</th>
                <th style="{ths}">Issuer</th>
                <th style="{ths}">Days Left</th>
                <th style="{ths}">Protocol</th>
                <th style="{ths}">Grade</th>
            </tr>"""
        for row in table_data:
            gc = GRADE_COLORS_HTML.get(row.get("grade", "-"), "#6b7280")
            valid_color = "#22c55e" if row["valid"] == "Yes" else "#ef4444" if row["valid"] == "No" else "#6b7280"
            html += f"""<tr>
                <td style="{tds}color:#58a6ff;font-family:monospace;">{_esc(row["subdomain"])}</td>
                <td style="{tds}font-family:monospace;">{row["ip"]}</td>
                <td style="{tds}color:{valid_color};font-weight:bold;">{row["valid"]}</td>
                <td style="{tds}">{row["issuer"]}</td>
                <td style="{tds}text-align:right;">{row["days_left"]}</td>
                <td style="{tds}">{row["protocol"]}</td>
                <td style="{tds}color:{gc};font-weight:bold;">{row["grade"]}</td>
            </tr>"""
        html += "</table>"
        return html

    elif table_type == "http":
        html = f"""<table style="width:100%;border-collapse:collapse;">
            <tr style="border-bottom:1px solid #30363d;">
                <th style="{ths}">Subdomain</th>
                <th style="{ths}">Reachable</th>
                <th style="{ths}">HTTPS</th>
                <th style="{ths}">Status</th>
                <th style="{ths}">Server</th>
                <th style="{ths}">Time</th>
                <th style="{ths}">Redirect</th>
            </tr>"""
        for row in table_data:
            https_color = "#22c55e" if row["https"] == "Yes" else "#ef4444" if row["reachable"] == "Yes" else "#6b7280"
            ms = row.get("response_ms", "-")
            html += f"""<tr>
                <td style="{tds}color:#58a6ff;font-family:monospace;">{_esc(row["subdomain"])}</td>
                <td style="{tds}">{row["reachable"]}</td>
                <td style="{tds}color:{https_color};font-weight:bold;">{row["https"]}</td>
                <td style="{tds}">{row["status"]}</td>
                <td style="{tds}">{row["server"]}</td>
                <td style="{tds}text-align:right;">{ms}</td>
                <td style="{tds}font-size:11px;word-break:break-all;">{row["redirect"]}</td>
            </tr>"""
        html += "</table>"
        return html

    return ""


def display_colab(result: AuditResult) -> None:
    import uuid

    from IPython.display import HTML
    from IPython.display import display as ipy_display

    domain = _esc(result.domain)
    grade_color = GRADE_COLORS_HTML.get(result.overall_grade, "#6b7280")
    uid = f"da{uuid.uuid4().hex[:8]}"

    # Map check types to subdomain table findings for consolidation
    sub_tables: dict[str, dict] = {}
    if "subdomains" in result.results:
        for f in result.results["subdomains"].findings:
            tt = f.get("table_type")
            if tt:
                sub_tables[tt] = f

    MODULE_TO_TABLE = {"ssl": "ssl", "dns": "dns", "headers": "http"}

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
            summary = (
                f'<span style="color:#8b949e;">{_esc(r.findings[0].get("detail", "")) if r.findings else "OK"}</span>'
            )

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
            detail = _esc(f.get("detail", ""))
            fix = _esc(f.get("fix", ""))
            parsed = f.get("parsed_record", [])
            tests = f.get("tests", [])

            # If finding has parsed record + tests, render MXToolbox-style
            if tests:
                rec_type = _esc(f.get("record_type", f.get("label", "")))
                raw_val = _esc(str(f.get("value", "")) if not isinstance(f.get("value"), str) else f.get("value", ""))

                findings_html += f"""
                <div style="margin:8px;padding:12px;background:#161b22;border-radius:8px;border-left:3px solid {fc};">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                        <span style="color:{fc};font-weight:bold;font-size:16px;">{fg}</span>
                        <span style="font-weight:bold;font-size:14px;">{rec_type}</span>
                        <span style="color:#8b949e;font-size:12px;">{domain}</span>
                    </div>"""

                # Raw record
                if raw_val and raw_val != "Not found":
                    findings_html += f"""
                    <div style="padding:6px 10px;background:#0d1117;border-radius:4px;margin-bottom:10px;font-family:monospace;font-size:12px;color:#8b949e;word-break:break-all;">
                        {raw_val}
                    </div>"""

                # Parsed record table
                if parsed:
                    findings_html += """
                    <table style="width:100%;border-collapse:collapse;margin-bottom:10px;font-size:12px;">
                        <tr style="border-bottom:1px solid #30363d;">
                            <th style="padding:6px 8px;text-align:left;color:#8b949e;width:50px;">Tag</th>
                            <th style="padding:6px 8px;text-align:left;color:#8b949e;">Value</th>
                            <th style="padding:6px 8px;text-align:left;color:#8b949e;width:100px;">Name</th>
                            <th style="padding:6px 8px;text-align:left;color:#8b949e;">Description</th>
                        </tr>"""
                    for row in parsed:
                        val_display = _esc(row["value"])
                        if len(val_display) > 60:
                            val_display = val_display[:57] + "..."
                        findings_html += f"""
                        <tr style="border-bottom:1px solid #21262d;">
                            <td style="padding:5px 8px;color:#58a6ff;font-family:monospace;">{_esc(row["tag"])}</td>
                            <td style="padding:5px 8px;font-family:monospace;word-break:break-all;">{val_display}</td>
                            <td style="padding:5px 8px;font-weight:bold;">{_esc(row["name"])}</td>
                            <td style="padding:5px 8px;color:#8b949e;">{_esc(row["description"])}</td>
                        </tr>"""
                    findings_html += "</table>"

                # Validation tests table
                if tests:
                    findings_html += """
                    <table style="width:100%;border-collapse:collapse;font-size:12px;">
                        <tr style="border-bottom:1px solid #30363d;">
                            <th style="padding:6px 8px;width:24px;"></th>
                            <th style="padding:6px 8px;text-align:left;color:#8b949e;">Test</th>
                            <th style="padding:6px 8px;text-align:left;color:#8b949e;">Result</th>
                        </tr>"""
                    for t in tests:
                        icon = (
                            '<span style="color:#22c55e;font-size:14px;">&#10004;</span>'
                            if t["pass"]
                            else '<span style="color:#ef4444;font-size:14px;">&#10008;</span>'
                        )
                        result_color = "#e6edf3" if t["pass"] else "#f87171"
                        findings_html += f"""
                        <tr style="border-bottom:1px solid #21262d;background:{"#0d1117" if t["pass"] else "#1a0d0d"};">
                            <td style="padding:6px 8px;text-align:center;">{icon}</td>
                            <td style="padding:6px 8px;font-weight:bold;">{_esc(t["test"])}</td>
                            <td style="padding:6px 8px;color:{result_color};">{_esc(t["result"])}</td>
                        </tr>"""
                    findings_html += "</table>"

                # Fix
                if fix:
                    findings_html += f'<div style="color:#58a6ff;font-size:12px;margin-top:8px;">Fix: {fix}</div>'

                findings_html += "</div>"

            # Subdomain data table
            elif f.get("table_type"):
                table_type = f["table_type"]
                table_data = f.get("table_data", [])

                if table_data:
                    findings_html += f"""
                    <div style="margin:8px;padding:12px;background:#161b22;border-radius:8px;border-left:3px solid {fc};">
                        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                            <span style="color:{fc};font-weight:bold;font-size:14px;">{fg}</span>
                            <span style="font-weight:bold;font-size:13px;">{f.get("label", "")}</span>
                            <span style="color:#8b949e;font-size:12px;">{detail}</span>
                        </div>"""

                    findings_html += colab_data_table(table_type, table_data)

                    if fix:
                        findings_html += f'<div style="color:#58a6ff;font-size:12px;margin-top:8px;">Fix: {fix}</div>'
                    findings_html += "</div>"

            # Standard finding (non-detailed)
            elif fg in ("A", "-"):
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

        # Append matching subdomain table into this module's detail
        sub_table_html = ""
        table_key = MODULE_TO_TABLE.get(mod)
        if table_key and table_key in sub_tables:
            sf = sub_tables[table_key]
            sf_detail = _esc(sf.get("detail", ""))
            sf_label = _esc(sf.get("label", ""))
            sub_table_html = f"""
            <div style="margin:12px 8px 4px;padding-top:10px;border-top:1px solid #30363d;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                    <span style="font-weight:bold;font-size:13px;">Subdomains &mdash; {sf_label}</span>
                    <span style="color:#8b949e;font-size:12px;">{sf_detail}</span>
                </div>
                {colab_data_table(table_key, sf.get("table_data", []))}
            </div>"""

        # For subdomains module, show discovery summary + clickable subdomain list
        if mod == "subdomains":
            non_table_html = ""
            for f in r.findings:
                if not f.get("table_type"):
                    d = _esc(f.get("detail", ""))
                    non_table_html += f'<div style="padding:6px 14px;color:#8b949e;font-size:13px;">{d}</div>'
                    sub_list = f.get("subdomain_list", [])
                    if sub_list:
                        subs_html = "".join(
                            f'<span style="display:inline-block;padding:3px 8px;margin:2px;background:#161b22;border:1px solid #21262d;border-radius:4px;font-family:monospace;font-size:12px;color:#58a6ff;">{_esc(s)}</span>'
                            for s in sub_list
                        )
                        non_table_html += (
                            f'<div style="padding:8px 14px;display:flex;flex-wrap:wrap;gap:0;">{subs_html}</div>'
                        )
            findings_html = non_table_html

        detail_panels += f"""
        <div id="{uid}_{mod}" style="display:none;background:#0d1117;border:1px solid #21262d;border-top:none;margin:-1px 0 12px 0;border-radius:0 0 8px 8px;padding:10px 4px;">
            <div style="padding:4px 14px 8px;color:#8b949e;font-size:11px;border-bottom:1px solid #21262d;margin-bottom:6px;">
                {domain} &rsaquo; {label} &mdash; Detail
            </div>
            {findings_html}
            {sub_table_html}
        </div>"""

    # ── Action items ──
    action_html = ""
    if result.action_items:
        items_html = ""
        for _i, item in enumerate(result.action_items, 1):
            sev = item["severity"]
            sev_color = SEVERITY_COLORS_HTML.get(sev, "#6b7280")
            mod_label = MODULE_LABELS.get(item.get("module", ""), item.get("module", ""))
            fix = _esc(item.get("fix", ""))

            items_html += f"""
            <div style="margin:6px 0;padding:10px 12px;background:#0d1117;border:1px solid #21262d;border-left:3px solid {sev_color};border-radius:0 6px 6px 0;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
                    <span style="color:{sev_color};font-weight:bold;font-size:10px;text-transform:uppercase;letter-spacing:1px;padding:2px 6px;background:{sev_color}18;border-radius:3px;">{sev}</span>
                    <span style="font-weight:bold;font-size:13px;">{_esc(item["issue"])}</span>
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
        var panels = [{", ".join(f"'{uid}_{mod}'" for mod in MODULE_ORDER if mod in result.results)}];
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
