"""Category-based tabular report — one table per check type, all domains sorted by risk."""
from __future__ import annotations

import html as html_mod
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from domain_audit.core import AuditResult


def _esc(text: str) -> str:
    return html_mod.escape(str(text)) if text else ""


GRADE_ORDER = {"F": 0, "C": 1, "B": 2, "A": 3, "-": 4, "?": 5}
GRADE_COLORS = {
    "A": "#22c55e", "B": "#eab308", "C": "#f97316", "F": "#ef4444",
    "?": "#6b7280", "-": "#6b7280",
}


def render_html(result: AuditResult, grade_filter: str = "all") -> str:
    """Build full HTML report with one table per category, sorted by risk.

    Args:
        grade_filter: Pre-select a grade filter. "all" shows everything,
                      "F"/"C"/"B"/"A" pre-activates that filter on load.
    """
    domain = _esc(result.domain)
    gc = GRADE_COLORS.get(result.overall_grade, "#6b7280")

    # Unique ID for filter JS (needed before sections)
    import uuid
    uid = f"rpt{uuid.uuid4().hex[:8]}"

    sections = []

    # ── 1. SSL/TLS table ──
    ssl_rows = _build_ssl_rows(result)
    if ssl_rows:
        sections.append(_render_section("SSL / TLS", "Certificate health across all domains", ssl_rows, [
            ("Domain", "domain", True),
            ("Grade", "grade", False),
            ("Valid", "valid", False),
            ("Issuer", "issuer", False),
            ("Days Left", "days_left", False),
            ("Protocol", "protocol", False),
        ], uid=uid))

    # ── 2. DNS table ──
    dns_rows = _build_dns_rows(result)
    if dns_rows:
        sections.append(_render_section("DNS Records", "Record resolution across all domains", dns_rows, [
            ("Domain", "domain", True),
            ("A", "a", False),
            ("AAAA", "aaaa", False),
            ("CNAME", "cname", False),
            ("MX", "mx", False),
            ("NS", "ns", False),
        ], uid=uid))

    # ── 3. HTTP table ──
    http_rows = _build_http_rows(result)
    if http_rows:
        sections.append(_render_section("HTTP / Headers", "Reachability and security headers", http_rows, [
            ("Domain", "domain", True),
            ("Grade", "grade", False),
            ("HTTPS", "https", False),
            ("HSTS", "hsts", False),
            ("CSP", "csp", False),
            ("Status", "status", False),
            ("Server", "server", False),
            ("Time", "response_ms", False),
        ], uid=uid))

    # ── 4. Email Security table ──
    email_rows = _build_email_rows(result)
    if email_rows:
        sections.append(_render_section("Email Security", "SPF, DKIM, DMARC status", email_rows, [
            ("Domain", "domain", True),
            ("Grade", "grade", False),
            ("SPF", "spf", False),
            ("DKIM", "dkim", False),
            ("DMARC", "dmarc", False),
            ("SPF Lookups", "spf_lookups", False),
        ], uid=uid))

    # ── 5. Open Ports table ──
    ports_rows = _build_ports_rows(result)
    if ports_rows:
        sections.append(_render_section("Open Ports", "Exposed services", ports_rows, [
            ("Domain", "domain", True),
            ("Grade", "grade", False),
            ("Open Ports", "open_ports", False),
            ("Dangerous", "dangerous", False),
        ], uid=uid))

    # ── 6. WHOIS table ──
    whois_rows = _build_whois_rows(result)
    if whois_rows:
        sections.append(_render_section("WHOIS", "Domain registration", whois_rows, [
            ("Domain", "domain", True),
            ("Grade", "grade", False),
            ("Registrar", "registrar", False),
            ("Days Left", "days_left", False),
        ], uid=uid))

    # ── 7. Tech Stack table ──
    tech_rows = _build_tech_rows(result)
    if tech_rows:
        sections.append(_render_section("Tech Stack", "Detected technologies", tech_rows, [
            ("Domain", "domain", True),
            ("Technologies", "techs", False),
        ], uid=uid))

    # ── Action Items ──
    action_html = _render_actions(result)

    body = "\n".join(sections)

    # Pre-select filter from parameter
    initial_filter = grade_filter.upper() if grade_filter and grade_filter.lower() != "all" else ""

    filter_bar = f"""
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:20px;padding:10px 14px;background:#161b22;border-radius:8px;flex-wrap:wrap;">
        <span style="font-size:12px;color:#8b949e;margin-right:4px;">Filter:</span>
        <button onclick="{uid}_filter('F')" id="{uid}_btn_F" style="cursor:pointer;padding:4px 12px;border:2px solid #ef4444;border-radius:6px;background:#ef444420;color:#ef4444;font-weight:bold;font-size:13px;">F &middot; Fail</button>
        <button onclick="{uid}_filter('C')" id="{uid}_btn_C" style="cursor:pointer;padding:4px 12px;border:2px solid #f97316;border-radius:6px;background:#f9731620;color:#f97316;font-weight:bold;font-size:13px;">C &middot; Warn</button>
        <button onclick="{uid}_filter('B')" id="{uid}_btn_B" style="cursor:pointer;padding:4px 12px;border:2px solid #eab308;border-radius:6px;background:#eab30820;color:#eab308;font-weight:bold;font-size:13px;">B &middot; OK</button>
        <button onclick="{uid}_filter('A')" id="{uid}_btn_A" style="cursor:pointer;padding:4px 12px;border:2px solid #22c55e;border-radius:6px;background:#22c55e20;color:#22c55e;font-weight:bold;font-size:13px;">A &middot; Pass</button>
        <button onclick="{uid}_filter('all')" id="{uid}_btn_all" style="cursor:pointer;padding:4px 12px;border:2px solid #58a6ff;border-radius:6px;background:#58a6ff20;color:#58a6ff;font-weight:bold;font-size:12px;">Select All</button>
    </div>
    <script>
    var {uid}_active = new Set();
    function {uid}_filter(grade) {{
        if (grade === 'all') {{
            {uid}_active.clear();
        }} else if ({uid}_active.has(grade)) {{
            {uid}_active.delete(grade);
        }} else {{
            {uid}_active.add(grade);
        }}
        {uid}_applyFilter();
    }}
    function {uid}_applyFilter() {{
        ['F','C','B','A'].forEach(function(g) {{
            var btn = document.getElementById('{uid}_btn_' + g);
            if ({uid}_active.size === 0 || {uid}_active.has(g)) {{
                btn.style.opacity = '1';
            }} else {{
                btn.style.opacity = '0.3';
            }}
        }});
        document.getElementById('{uid}_btn_all').style.opacity = {uid}_active.size === 0 ? '1' : '0.5';
        var rows = document.querySelectorAll('[data-{uid}-grade]');
        rows.forEach(function(row) {{
            var rowGrade = row.getAttribute('data-{uid}-grade');
            if ({uid}_active.size === 0 || {uid}_active.has(rowGrade)) {{
                row.style.display = '';
            }} else {{
                row.style.display = 'none';
            }}
        }});
    }}
    // Apply initial filter if set
    (function() {{
        var init = '{initial_filter}';
        if (init && ['F','C','B','A'].indexOf(init) >= 0) {{
            {uid}_active.add(init);
            {uid}_applyFilter();
        }}
    }})();
    </script>
    """

    # ── Build header info boxes ──
    # Box 1: Audit grade (left-aligned)
    box1 = f"""
    <div style="flex:1;min-width:180px;padding:16px 20px;background:#161b22;border-radius:10px;border:1px solid #30363d;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:#6b7280;margin-bottom:4px;">Domain Audit Report</div>
        <div style="font-size:22px;font-weight:bold;color:#fff;margin-bottom:8px;font-family:monospace;">{domain}</div>
        <div style="display:flex;align-items:center;gap:12px;">
            <div style="font-size:42px;font-weight:bold;color:{gc};line-height:1;">{result.overall_grade}</div>
            <div>
                <div style="font-size:12px;color:{gc};text-transform:uppercase;letter-spacing:1px;font-weight:600;">Overall</div>
                <div style="font-size:11px;color:#484f58;">Scanned in {result.elapsed:.1f}s</div>
            </div>
        </div>
    </div>"""

    # Box 2: WHOIS summary
    whois_raw = result.results.get("whois", None)
    if whois_raw:
        wd = whois_raw.raw_data
        w_registrar = _esc(str(wd.get("registrar") or "Unknown"))
        w_created = _esc(str(wd.get("creation_date") or "-"))[:10]
        w_expires = _esc(str(wd.get("expiration_date") or "-"))[:10]
        w_days = wd.get("days_to_expiry")
        w_days_str = f"{w_days} days" if w_days is not None else "-"
        w_dnssec = "Yes" if wd.get("dnssec_enabled") else "No"
        w_privacy = "Yes" if wd.get("privacy_protected") else "No"
        w_dnssec_color = "#22c55e" if wd.get("dnssec_enabled") else "#ef4444"
        w_days_color = "#22c55e" if (w_days or 0) > 90 else "#eab308" if (w_days or 0) > 30 else "#ef4444"
    else:
        w_registrar = w_created = w_expires = w_days_str = w_dnssec = w_privacy = "-"
        w_dnssec_color = w_days_color = "#6b7280"

    box2 = f"""
    <div style="flex:1;min-width:200px;padding:16px 20px;background:#161b22;border-radius:10px;border:1px solid #30363d;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:#6b7280;margin-bottom:10px;">WHOIS</div>
        <table style="width:100%;font-size:12px;border-collapse:collapse;">
            <tr><td style="color:#8b949e;padding:2px 0;">Registrar</td><td style="text-align:right;font-weight:600;padding:2px 0;">{w_registrar}</td></tr>
            <tr><td style="color:#8b949e;padding:2px 0;">Created</td><td style="text-align:right;padding:2px 0;">{w_created}</td></tr>
            <tr><td style="color:#8b949e;padding:2px 0;">Expires</td><td style="text-align:right;color:{w_days_color};font-weight:600;padding:2px 0;">{w_expires} ({w_days_str})</td></tr>
            <tr><td style="color:#8b949e;padding:2px 0;">DNSSEC</td><td style="text-align:right;color:{w_dnssec_color};font-weight:600;padding:2px 0;">{w_dnssec}</td></tr>
            <tr><td style="color:#8b949e;padding:2px 0;">Privacy</td><td style="text-align:right;padding:2px 0;">{w_privacy}</td></tr>
        </table>
    </div>"""

    # Box 3: Tech stack summary
    tech_raw = result.results.get("tech", None)
    if tech_raw:
        techs = tech_raw.raw_data.get("technologies", [])
        tech_items = ""
        for t in techs[:8]:  # Limit to 8 in header
            cat = _esc(t.get("source", "").split(":")[0] if t.get("source") else "")
            name = _esc(t.get("name", ""))
            tech_items += f'<div style="display:flex;justify-content:space-between;padding:2px 0;font-size:12px;"><span style="color:#8b949e;">{cat}</span><span style="font-weight:600;">{name}</span></div>'
        if not techs:
            tech_items = '<div style="color:#6b7280;font-size:12px;">None detected</div>'
        if len(techs) > 8:
            tech_items += f'<div style="color:#6b7280;font-size:11px;padding-top:4px;">+{len(techs) - 8} more</div>'
    else:
        tech_items = '<div style="color:#6b7280;font-size:12px;">Scanner not run</div>'

    box3 = f"""
    <div style="flex:1;min-width:200px;padding:16px 20px;background:#161b22;border-radius:10px;border:1px solid #30363d;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;color:#6b7280;margin-bottom:10px;">Tech Stack</div>
        {tech_items}
    </div>"""

    header_row = f"""
    <div style="display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap;">
        {box1}{box2}{box3}
    </div>"""

    return f"""
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#010409;color:#e6edf3;padding:24px;border-radius:12px;max-width:100%;width:100%;" id="{uid}_root">
        {header_row}
        {filter_bar}
        {body}
        {action_html}
    </div>
    """


def display(result: AuditResult, grade_filter: str = "all") -> None:
    """Render the tabular report in Colab or as raw HTML.

    Args:
        grade_filter: Pre-select a grade filter. "all" shows everything,
                      "F"/"C"/"B"/"A" pre-activates that filter on load.
    """
    try:
        from IPython.display import display as ipy_display, HTML
        ipy_display(HTML(render_html(result, grade_filter=grade_filter)))
    except ImportError:
        print(render_html(result, grade_filter=grade_filter))


# ═══════════════════════════════════════════════════════════════════
#  Row builders — extract data from AuditResult into flat rows
# ═══════════════════════════════════════════════════════════════════

def _build_ssl_rows(result: AuditResult) -> list[dict]:
    rows = []

    # Main domain SSL
    if "ssl" in result.results:
        r = result.results["ssl"]
        for f in r.findings:
            if f.get("label") == "Certificate expiration":
                val = f.get("value", {})
                days = val.get("days_left", "?") if isinstance(val, dict) else "?"
                rows.append({
                    "domain": result.domain,
                    "grade": r.grade,
                    "valid": "Yes" if r.grade != "?" else "No",
                    "issuer": _find_finding(r, "Certificate issuer"),
                    "days_left": str(days),
                    "protocol": _find_finding(r, "Protocol version"),
                })
                break
        else:
            if r.status == "error":
                rows.append({
                    "domain": result.domain, "grade": "?", "valid": "Error",
                    "issuer": "-", "days_left": "-", "protocol": "-",
                })

    # Subdomain SSL from probes
    if "subdomains" in result.results:
        raw = result.results["subdomains"].raw_data
        for probe in raw.get("probes", []):
            s = probe.get("ssl", {})
            ips = probe.get("dns", {}).get("a", [])
            if s.get("has_ssl"):
                grade = "A" if (s.get("days_left") or 0) > 90 else "B" if (s.get("days_left") or 0) > 30 else "C" if (s.get("days_left") or 0) > 0 else "F"
                if not s.get("valid"):
                    grade = "F"
                rows.append({
                    "domain": probe["subdomain"],
                    "grade": grade,
                    "valid": "Yes" if s.get("valid") else "Invalid",
                    "issuer": s.get("issuer") or "-",
                    "days_left": str(s.get("days_left", "-")),
                    "protocol": s.get("protocol") or "-",
                })
            else:
                rows.append({
                    "domain": probe["subdomain"],
                    "grade": "-",
                    "valid": "No SSL",
                    "issuer": "-",
                    "days_left": "-",
                    "protocol": "-",
                })

    rows.sort(key=lambda r: GRADE_ORDER.get(r["grade"], 99))
    return rows


def _build_dns_rows(result: AuditResult) -> list[dict]:
    rows = []

    # Main domain DNS
    if "dns" in result.results:
        raw = result.results["dns"].raw_data
        rows.append({
            "domain": result.domain,
            "a": ", ".join(raw.get("A", [])) or "-",
            "aaaa": ", ".join(raw.get("AAAA", [])) or "-",
            "cname": ", ".join(raw.get("CNAME", [])) or "-",
            "mx": ", ".join(raw.get("MX", [])) or "-",
            "ns": ", ".join(raw.get("NS", [])) or "-",
        })

    # Subdomain DNS from probes
    if "subdomains" in result.results:
        for probe in result.results["subdomains"].raw_data.get("probes", []):
            d = probe.get("dns", {})
            rows.append({
                "domain": probe["subdomain"],
                "a": ", ".join(d.get("a", [])) or "-",
                "aaaa": ", ".join(d.get("aaaa", [])) or "-",
                "cname": ", ".join(d.get("cname", [])) or "-",
                "mx": "-",
                "ns": "-",
            })

    return rows


def _build_http_rows(result: AuditResult) -> list[dict]:
    rows = []

    # Main domain headers
    if "headers" in result.results:
        r = result.results["headers"]
        raw_headers = r.raw_data.get("headers", {})
        hl = {k.lower(): v for k, v in raw_headers.items()}
        rows.append({
            "domain": result.domain,
            "grade": r.grade,
            "https": "Yes",
            "hsts": "Yes" if "strict-transport-security" in hl else "No",
            "csp": "Yes" if "content-security-policy" in hl else "No",
            "status": "200",
            "server": hl.get("server", "-"),
            "response_ms": "-",
        })

    # Subdomain HTTP from probes
    if "subdomains" in result.results:
        for probe in result.results["subdomains"].raw_data.get("probes", []):
            h = probe.get("http", {})
            if h.get("reachable"):
                ms = h.get("response_ms")
                rows.append({
                    "domain": probe["subdomain"],
                    "grade": "-",
                    "https": "Yes" if h.get("https") else "No",
                    "hsts": "-",
                    "csp": "-",
                    "status": str(h.get("status_code", "-")),
                    "server": h.get("server") or "-",
                    "response_ms": "{}ms".format(ms) if ms is not None else "-",
                })

    # Sort: failures first, then by grade
    def _http_sort(r):
        if r["https"] == "No":
            return 0
        return GRADE_ORDER.get(r["grade"], 99)
    rows.sort(key=_http_sort)
    return rows


def _build_email_rows(result: AuditResult) -> list[dict]:
    rows = []
    if "email" in result.results:
        r = result.results["email"]
        raw = r.raw_data

        spf_data = raw.get("spf", {})
        dmarc_data = raw.get("dmarc", {})
        dkim_data = raw.get("dkim", {})

        spf_status = spf_data.get("grade", "?") if isinstance(spf_data, dict) else "?"
        dmarc_status = dmarc_data.get("grade", "?") if isinstance(dmarc_data, dict) else "?"

        dkim_found = dkim_data.get("found_selectors", []) if isinstance(dkim_data, dict) else []
        dkim_status = "A" if dkim_found else "C"

        spf_lookups = str(spf_data.get("lookup_count", "-")) if isinstance(spf_data, dict) else "-"

        rows.append({
            "domain": result.domain,
            "grade": r.grade,
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "spf_lookups": spf_lookups,
        })

    rows.sort(key=lambda r: GRADE_ORDER.get(r["grade"], 99))
    return rows


def _build_ports_rows(result: AuditResult) -> list[dict]:
    rows = []
    if "ports" in result.results:
        r = result.results["ports"]
        raw = r.raw_data
        open_ports = raw.get("open_ports", [])
        dangerous = [p for p in open_ports if p["port"] in {1433, 3306, 3389, 5432, 9200, 9300, 27017, 27018, 27019}]

        rows.append({
            "domain": result.domain,
            "grade": r.grade,
            "open_ports": ", ".join("{}/{}".format(p["port"], p["service"]) for p in open_ports) or "None",
            "dangerous": ", ".join("{}/{}".format(p["port"], p["service"]) for p in dangerous) or "None",
        })

    rows.sort(key=lambda r: GRADE_ORDER.get(r["grade"], 99))
    return rows


def _build_whois_rows(result: AuditResult) -> list[dict]:
    rows = []
    if "whois" in result.results:
        r = result.results["whois"]
        raw = r.raw_data
        rows.append({
            "domain": result.domain,
            "grade": r.grade,
            "registrar": raw.get("registrar") or "-",
            "days_left": _find_whois_days(r),
        })
    return rows


def _build_tech_rows(result: AuditResult) -> list[dict]:
    rows = []
    if "tech" in result.results:
        raw = result.results["tech"].raw_data
        techs = raw.get("technologies", [])
        rows.append({
            "domain": result.domain,
            "techs": ", ".join(t["name"] for t in techs) if techs else "None detected",
        })
    return rows


# ═══════════════════════════════════════════════════════════════════
#  HTML renderers
# ═══════════════════════════════════════════════════════════════════

def _render_section(title: str, subtitle: str, rows: list[dict], columns: list[tuple[str, str, bool]], uid: str = "") -> str:
    """Render one category section with header + table."""
    ths = "padding:8px 10px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:#8b949e;border-bottom:2px solid #30363d;"
    tds = "padding:6px 10px;font-size:13px;border-bottom:1px solid #21262d;"

    header_cells = "".join(f'<th style="{ths}">{col[0]}</th>' for col in columns)

    body_rows = ""
    for row in rows:
        row_grade = row.get("grade", "-")
        grade_attr = f' data-{uid}-grade="{row_grade}"' if uid else ""
        cells = ""
        for col_name, col_key, is_domain in columns:
            val = _esc(str(row.get(col_key, "-")))

            if is_domain:
                cells += f'<td style="{tds}color:#58a6ff;font-family:monospace;font-weight:bold;white-space:nowrap;">{val}</td>'
            elif col_key == "grade":
                gc = GRADE_COLORS.get(row.get("grade", "-"), "#6b7280")
                cells += f'<td style="{tds}color:{gc};font-weight:bold;font-size:16px;text-align:center;">{val}</td>'
            elif val in ("Yes", "No", "No SSL", "Invalid", "Error"):
                color = "#22c55e" if val == "Yes" else "#ef4444" if val in ("No", "Invalid", "Error") else "#6b7280"
                cells += f'<td style="{tds}color:{color};font-weight:bold;">{val}</td>'
            elif col_key == "dangerous" and val != "None":
                cells += f'<td style="{tds}color:#ef4444;font-weight:bold;">{val}</td>'
            else:
                cells += f'<td style="{tds}">{val}</td>'

        body_rows += f"<tr{grade_attr}>{cells}</tr>"

    return f"""
    <div style="margin-bottom:24px;">
        <div style="padding:10px 14px;background:#161b22;border-radius:8px 8px 0 0;border-bottom:2px solid #30363d;">
            <div style="font-weight:bold;font-size:15px;">{_esc(title)}</div>
            <div style="font-size:11px;color:#8b949e;">{_esc(subtitle)}</div>
        </div>
        <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;background:#0d1117;">
                <thead><tr>{header_cells}</tr></thead>
                <tbody>{body_rows}</tbody>
            </table>
        </div>
    </div>"""


def _render_actions(result: AuditResult) -> str:
    if not result.action_items:
        return ""

    domain = _esc(result.domain)
    sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#6b7280"}
    mod_labels = {
        "ssl": "SSL/TLS", "dns": "DNS", "subdomains": "Subdomains",
        "headers": "HTTP Headers", "whois": "WHOIS", "email": "Email Security",
        "ports": "Ports", "tech": "Tech",
    }

    items = ""
    for item in result.action_items:
        sev = item["severity"]
        sc = sev_colors.get(sev, "#6b7280")
        mod = mod_labels.get(item.get("module", ""), item.get("module", ""))
        fix = _esc(item.get("fix", ""))
        issue = _esc(item.get("issue", ""))

        items += f"""
        <tr style="border-bottom:1px solid #21262d;">
            <td style="padding:8px 10px;"><span style="color:{sc};font-weight:bold;font-size:11px;text-transform:uppercase;padding:2px 6px;background:{sc}18;border-radius:3px;">{sev}</span></td>
            <td style="padding:8px 10px;font-weight:bold;">{issue}</td>
            <td style="padding:8px 10px;color:#8b949e;">{domain} &rsaquo; {_esc(mod)}</td>
            <td style="padding:8px 10px;color:#58a6ff;font-size:12px;">{fix}</td>
        </tr>"""

    return f"""
    <div style="margin-top:24px;">
        <div style="padding:10px 14px;background:#2d1215;border-radius:8px 8px 0 0;border-bottom:2px solid #ef4444;">
            <span style="font-weight:bold;font-size:15px;">Action Items</span>
            <span style="color:#f87171;font-size:12px;margin-left:8px;">{len(result.action_items)} issue(s) for {domain}</span>
        </div>
        <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;background:#0d1117;">
                <thead><tr>
                    <th style="padding:8px 10px;text-align:left;font-size:11px;text-transform:uppercase;color:#8b949e;border-bottom:2px solid #30363d;">Severity</th>
                    <th style="padding:8px 10px;text-align:left;font-size:11px;text-transform:uppercase;color:#8b949e;border-bottom:2px solid #30363d;">Issue</th>
                    <th style="padding:8px 10px;text-align:left;font-size:11px;text-transform:uppercase;color:#8b949e;border-bottom:2px solid #30363d;">Location</th>
                    <th style="padding:8px 10px;text-align:left;font-size:11px;text-transform:uppercase;color:#8b949e;border-bottom:2px solid #30363d;">Fix</th>
                </tr></thead>
                <tbody>{items}</tbody>
            </table>
        </div>
    </div>"""


# ═══════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════

def _find_finding(scan_result, label_contains: str) -> str:
    for f in scan_result.findings:
        if label_contains.lower() in f.get("label", "").lower():
            val = f.get("value", "-")
            return str(val) if not isinstance(val, (dict, list)) else "-"
    return "-"


def _find_whois_days(scan_result) -> str:
    for f in scan_result.findings:
        if "expiration" in f.get("label", "").lower():
            val = f.get("value", {})
            if isinstance(val, dict):
                return str(val.get("days_left", "-"))
    return "-"
