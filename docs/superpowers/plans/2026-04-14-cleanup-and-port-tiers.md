# Cleanup & Port Tier Restructure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor scanner infrastructure (httpx migration, dedup, Colab extraction) and restructure port grading with new WARNING_PORTS tier and expanded DANGEROUS_PORTS.

**Architecture:** Two-phase approach. Phase 1 (Tasks 1–7) is pure refactoring — same behavior, better code. Phase 2 (Tasks 8–11) introduces behavior changes to port grading and adds truncation logging. Each phase ends with a full test run and commit.

**Tech Stack:** Python 3.10+, httpx, pytest, rich

---

## File Map

**Modified:**
- `pyproject.toml` — dependency swap (requests → httpx), rich cap bump
- `README.md` — badge fix
- `domain_audit/scanners/headers.py` — requests → httpx
- `domain_audit/scanners/subdomains.py` — requests → httpx
- `domain_audit/scanners/tech_detect.py` — requests → httpx
- `domain_audit/scanners/dns_records.py` — requests → httpx, remove DANGEROUS_PORTS, import from ports
- `domain_audit/scanners/whois_info.py` — requests → httpx
- `domain_audit/scanners/ports.py` — new WARNING_PORTS, expanded DANGEROUS_PORTS/COMMON_PORTS, updated grading
- `domain_audit/core.py` — extract Colab progress to colab.py
- `domain_audit/report.py` — extract Colab display to colab.py
- `domain_audit/report_tables.py` — import _grade_ports from ports, delete duplicate
- `tests/test_ports.py` — new tests for WARNING_PORTS, expanded DANGEROUS_PORTS
- `tests/test_subdomains.py` — truncation logging test
- `tests/test_dns_records.py` — truncation logging test

**Created:**
- `domain_audit/colab.py` — extracted Colab detection, progress widget, and HTML report

---

## Phase 1: Refactoring (no behavior change)

### Task 1: Swap `requests` → `httpx` in pyproject.toml

**Files:**
- Modify: `pyproject.toml:31` (requests dependency)
- Modify: `pyproject.toml:35` (rich cap)

- [ ] **Step 1: Update pyproject.toml dependencies**

In `pyproject.toml`, replace the `requests` dependency and bump the `rich` cap:

```python
# OLD (line 31):
    "requests>=2.28",
# NEW:
    "httpx>=0.27",

# OLD (line 35):
    "rich>=12.4,<14",
# NEW:
    "rich>=12.4,<15",
```

- [ ] **Step 2: Install updated dependencies**

Run: `pip install -e ".[dev]"`
Expected: httpx installs successfully, requests may remain (other deps could pull it in — that's fine)

- [ ] **Step 3: Verify httpx is importable**

Run: `python -c "import httpx; print(httpx.__version__)"`
Expected: Version 0.27+ printed

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "build: swap requests for httpx, bump rich cap to <15"
```

---

### Task 2: Migrate `headers.py` to httpx

**Files:**
- Modify: `domain_audit/scanners/headers.py`

- [ ] **Step 1: Run existing tests to confirm baseline**

Run: `pytest tests/test_headers.py -v`
Expected: All tests pass (they mock `_fetch_headers`, so no real HTTP calls)

- [ ] **Step 2: Replace requests import and all requests.get calls**

In `domain_audit/scanners/headers.py`:

```python
# Line 6 — OLD:
import requests
# NEW:
import httpx
```

Replace every `requests.get(` with `httpx.get(` throughout the file. There are 4 occurrences (lines 175, 191, 220, 283).

For calls that use `allow_redirects=True`, change to `follow_redirects=True`:
- Line 175: `_fetch_headers` — change `allow_redirects=True` → `follow_redirects=True`
- Line 191: `_check_redirect_chain` first call — uses `allow_redirects=False` → `follow_redirects=False`
- Line 220: `_check_redirect_chain` loop — uses `allow_redirects=False` → `follow_redirects=False`
- Line 283: `_check_mixed_content` — uses `allow_redirects=True` → `follow_redirects=True`

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_headers.py -v`
Expected: All pass. Tests mock `_fetch_headers` directly, so the httpx swap is transparent.

- [ ] **Step 4: Commit**

```bash
git add domain_audit/scanners/headers.py
git commit -m "refactor: migrate headers scanner from requests to httpx"
```

---

### Task 3: Migrate `subdomains.py` to httpx

**Files:**
- Modify: `domain_audit/scanners/subdomains.py`

- [ ] **Step 1: Run existing tests to confirm baseline**

Run: `pytest tests/test_subdomains.py -v`
Expected: All tests pass

- [ ] **Step 2: Replace requests import and all requests.get calls**

In `domain_audit/scanners/subdomains.py`:

```python
# Line 13 — OLD:
import requests
# NEW:
import httpx
```

Replace every `requests.get(` with `httpx.get(` (3 occurrences at lines 30, 43, 235).

For redirect parameters:
- Line 30 (`_query_crtsh`): No redirect param — add nothing (httpx default no-redirect is fine for API calls, but crt.sh might redirect; add `follow_redirects=True` to be safe)
- Line 43 (`_query_certspotter`): Same — add `follow_redirects=True`
- Line 235 (`_probe_http`): `allow_redirects=True` → `follow_redirects=True`

For `resp.raise_for_status()` at lines 36 and 49: works identically in httpx.

For `resp.elapsed` at line 245: httpx also provides `resp.elapsed` as a `timedelta` — same behavior.

For `resp.url` at lines 244 and 246: httpx returns a `httpx.URL` object. Wrap in `str()`:

```python
# Line 244 — OLD:
data["https"] = scheme == "https" or resp.url.startswith("https://")
# NEW:
data["https"] = scheme == "https" or str(resp.url).startswith("https://")

# Line 246 — OLD:
if resp.url != f"{scheme}://{sub}" and resp.url != f"{scheme}://{sub}/":
    data["redirect"] = resp.url
# NEW:
final_url = str(resp.url)
if final_url != f"{scheme}://{sub}" and final_url != f"{scheme}://{sub}/":
    data["redirect"] = final_url
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_subdomains.py -v`
Expected: All pass. Tests mock `_discover_subdomains` and `_probe_subdomain`, not raw HTTP.

- [ ] **Step 4: Commit**

```bash
git add domain_audit/scanners/subdomains.py
git commit -m "refactor: migrate subdomains scanner from requests to httpx"
```

---

### Task 4: Migrate `tech_detect.py`, `dns_records.py`, and `whois_info.py` to httpx

**Files:**
- Modify: `domain_audit/scanners/tech_detect.py`
- Modify: `domain_audit/scanners/dns_records.py`
- Modify: `domain_audit/scanners/whois_info.py`

- [ ] **Step 1: Run existing tests to confirm baseline**

Run: `pytest tests/test_tech_detect.py tests/test_dns_records.py tests/test_whois_info.py -v`
Expected: All pass

- [ ] **Step 2: Migrate tech_detect.py**

In `domain_audit/scanners/tech_detect.py`:

```python
# Line 15 — OLD:
import requests
# NEW:
import httpx
```

Replace `requests.get(` with `httpx.get(` at line 320 (`_fetch_page`).
Change `allow_redirects=True` → `follow_redirects=True`.

- [ ] **Step 3: Migrate dns_records.py**

In `domain_audit/scanners/dns_records.py`, the import is inline at line 120:

```python
# Line 120 — OLD:
    import requests
# NEW:
    import httpx
```

Replace `requests.get(` with `httpx.get(` at line 146.
This call has no `allow_redirects` param — httpx defaults to not following, which is fine for a direct API call to ip-api.com.

- [ ] **Step 4: Migrate whois_info.py**

In `domain_audit/scanners/whois_info.py`, the import is inline at line 25:

```python
# Line 25 — OLD:
    import requests
# NEW:
    import httpx
```

Replace `requests.get(` with `httpx.get(` at lines 30 and 44.
Line 44 uses `resp.raise_for_status()` — works identically in httpx.
Add `follow_redirects=True` to both calls (RDAP/IANA APIs may redirect).

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_tech_detect.py tests/test_dns_records.py tests/test_whois_info.py -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add domain_audit/scanners/tech_detect.py domain_audit/scanners/dns_records.py domain_audit/scanners/whois_info.py
git commit -m "refactor: migrate tech_detect, dns_records, whois_info from requests to httpx"
```

---

### Task 5: Deduplicate DANGEROUS_PORTS and port grading

**Files:**
- Modify: `domain_audit/scanners/dns_records.py:94-101` (delete DANGEROUS_PORTS dict)
- Modify: `domain_audit/scanners/dns_records.py:163` (update loop)
- Modify: `domain_audit/report_tables.py:8-12, 22-32` (delete duplicate grading)

- [ ] **Step 1: Write test for deduplication — verify dns_records uses all 9 dangerous ports**

In `tests/test_dns_records.py`, add a test that confirms the dangerous ports match:

```python
from domain_audit.scanners.ports import DANGEROUS_PORTS as PORTS_DANGEROUS
from domain_audit.scanners.dns_records import DANGEROUS_PORTS as DNS_DANGEROUS


def test_dangerous_ports_match():
    """After dedup, dns_records should use the same DANGEROUS_PORTS as ports."""
    assert DNS_DANGEROUS == PORTS_DANGEROUS
```

- [ ] **Step 2: Run test to verify it fails (sets don't match yet)**

Run: `pytest tests/test_dns_records.py::test_dangerous_ports_match -v`
Expected: FAIL — dns_records has 6 ports (dict keys as set), ports has 9 ports (set)

- [ ] **Step 3: Delete DANGEROUS_PORTS from dns_records.py, import from ports**

In `domain_audit/scanners/dns_records.py`:

Delete lines 94-101 (the `DANGEROUS_PORTS` dict).

Add import near the top (after existing imports, around line 16):

```python
from domain_audit.scanners.ports import COMMON_PORTS, DANGEROUS_PORTS
```

Update `_check_ips()` at line 163 — the old code iterated `DANGEROUS_PORTS.items()` (dict). Now iterate `DANGEROUS_PORTS` (set) and look up service names from `COMMON_PORTS`:

```python
        # Quick scan of dangerous ports on this IP
        open_dangerous = []
        for port in sorted(DANGEROUS_PORTS):
            service = COMMON_PORTS.get(port, "unknown")
            if _check_port(ip, port):
                open_dangerous.append({"port": port, "service": service})
        info["open_dangerous_ports"] = open_dangerous
```

Also delete the `_check_port` import of `is_private_ip` duplicate if the function references it — actually `_check_port` in dns_records.py is a local function (line 104), not imported from ports. Leave it.

- [ ] **Step 4: Run dedup test**

Run: `pytest tests/test_dns_records.py::test_dangerous_ports_match -v`
Expected: PASS (now both reference the same object)

- [ ] **Step 5: Delete duplicate grading in report_tables.py**

In `domain_audit/report_tables.py`:

Update the import block (lines 8-12):

```python
# OLD:
from domain_audit.scanners.ports import (
    ACCEPTABLE_PORTS,
    DANGEROUS_PORTS,
    EXPECTED_PORTS,
)
# NEW:
from domain_audit.scanners.ports import (
    DANGEROUS_PORTS,
    _grade_ports,
)
```

Delete `_grade_host_ports()` function (lines 22-32).

Replace every call to `_grade_host_ports(...)` with `_grade_ports(...)`. There is one call at line 564 (`_build_ports_rows`):

```python
# OLD:
grade = _grade_host_ports({p["port"] for p in open_ports})
# NEW:
grade = _grade_ports({p["port"] for p in open_ports})
```

- [ ] **Step 6: Run full test suite**

Run: `pytest -v`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add domain_audit/scanners/dns_records.py domain_audit/report_tables.py tests/test_dns_records.py
git commit -m "refactor: deduplicate DANGEROUS_PORTS and port grading logic"
```

---

### Task 6: Extract Colab code to `domain_audit/colab.py`

**Files:**
- Create: `domain_audit/colab.py`
- Modify: `domain_audit/core.py`
- Modify: `domain_audit/report.py`

- [ ] **Step 1: Run existing tests to confirm baseline**

Run: `pytest tests/test_core.py -v`
Expected: All pass

- [ ] **Step 2: Create `domain_audit/colab.py`**

Create `domain_audit/colab.py` with the following content — moved from core.py and report.py:

```python
"""Google Colab integration — detection, progress widget, and HTML report rendering."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from domain_audit.grader import ScanResult


def is_colab() -> bool:
    """Detect if running inside Google Colab."""
    try:
        from google.colab import output  # noqa: F401

        return True
    except ImportError:
        return False
```

Then copy `_make_progress_colab` from `core.py:108-188` into `colab.py` as `make_progress_colab`. Keep all the internal logic identical. The function signature stays:

```python
def make_progress_colab(domain: str, scanner_names: list[str]) -> Callable[[str, ScanResult | None], None]:
```

Import `_MODULE_LABELS` and `_STATUS_ICON` from `core.py` — but wait, that creates a circular import (core imports colab, colab imports core). Instead, pass `module_labels` and `status_icon` dicts as parameters:

```python
def make_progress_colab(
    domain: str,
    scanner_names: list[str],
    module_labels: dict[str, str],
    status_icon: dict[str, str],
) -> Callable[[str, ScanResult | None], None]:
```

Then copy the Colab display functions from `report.py`:
- `_colab_data_table()` (report.py lines 358-433) → `colab_data_table()`
- `_display_colab()` (report.py lines 436-end) → `display_colab()`

These import from `report.py`: `_esc`, `GRADE_COLORS_HTML`, `GRADE_LABEL_HTML`, `MODULE_LABELS`, `MODULE_ORDER`, `SEVERITY_COLORS_HTML`. Import them at the top of `colab.py`:

```python
from domain_audit.report import (
    _esc,
    GRADE_COLORS_HTML,
    GRADE_LABEL_HTML,
    MODULE_LABELS,
    MODULE_ORDER,
    SEVERITY_COLORS_HTML,
)
```

This import is safe — `report.py` will import from `colab.py` lazily (inside the `display()` function body), so no circular import at module load time.

- [ ] **Step 3: Update core.py — replace inline Colab code with imports**

In `domain_audit/core.py`:

Delete `_is_colab()` (lines 99-105) and `_make_progress_colab()` (lines 108-188).

Add import at top of file (after existing imports):

```python
from domain_audit.colab import is_colab, make_progress_colab
```

Update `audit()` function:
- Line 258: `_is_colab()` → `is_colab()`
- Line 261: `_is_colab()` → `is_colab()`
- Line 262: `_make_progress_colab(domain, scanner_names)` → `make_progress_colab(domain, scanner_names, _MODULE_LABELS, _STATUS_ICON)`
- Line 355: `_is_colab()` → `is_colab()`

- [ ] **Step 4: Update report.py — replace inline Colab code with lazy import**

In `domain_audit/report.py`:

Delete `_is_colab()` (lines 70-76), `_colab_data_table()` (lines 358-433), and `_display_colab()` (lines 436 to end of file).

Update `display()` function (currently at line 79):

```python
def display(result: AuditResult) -> None:
    from domain_audit.colab import is_colab

    if is_colab():
        from domain_audit.colab import display_colab

        display_colab(result)
    else:
        _display_terminal(result)
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_core.py -v`
Expected: All pass

- [ ] **Step 6: Run full test suite**

Run: `pytest -v`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add domain_audit/colab.py domain_audit/core.py domain_audit/report.py
git commit -m "refactor: extract Colab code into domain_audit/colab.py"
```

---

### Task 7: Fix README badge

**Files:**
- Modify: `README.md:13`

- [ ] **Step 1: Fix the badge**

In `README.md`, line 13:

```html
<!-- OLD: -->
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"></a>
<!-- NEW: -->
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"></a>
```

- [ ] **Step 2: Run full test suite to verify Phase 1 is clean**

Run: `pytest -v`
Expected: All tests pass, no behavior changes

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: fix Python version badge to match requires-python 3.10+"
```

---

## Phase 2: Behavior Changes

### Task 8: Add WARNING_PORTS tier and restructure port grading

**Files:**
- Modify: `domain_audit/scanners/ports.py`
- Test: `tests/test_ports.py`

- [ ] **Step 1: Write failing tests for new grading behavior**

Add to `tests/test_ports.py`:

```python
from domain_audit.scanners.ports import (
    ACCEPTABLE_PORTS,
    DANGEROUS_PORTS,
    WARNING_PORTS,
    _grade_ports,
    PORT_CLOSED,
    PORT_OPEN,
    scan,
)


class TestGradePorts:
    def test_only_expected_ports(self):
        assert _grade_ports({80, 443}) == "A"

    def test_empty_ports(self):
        assert _grade_ports(set()) == "A"

    def test_acceptable_port_ssh(self):
        assert _grade_ports({80, 443, 22}) == "B"

    def test_warning_port_smtp(self):
        """Port 25 should trigger grade C (WARNING_PORTS tier)."""
        assert _grade_ports({80, 443, 25}) == "C"

    def test_dangerous_port_ftp(self):
        """FTP (21) should trigger grade F."""
        assert _grade_ports({80, 443, 21}) == "F"

    def test_dangerous_port_telnet(self):
        """Telnet (23) should trigger grade F."""
        assert _grade_ports({80, 443, 23}) == "F"

    def test_dangerous_port_pop3(self):
        """POP3 (110) should trigger grade F."""
        assert _grade_ports({80, 443, 110}) == "F"

    def test_dangerous_port_imap(self):
        """IMAP (143) should trigger grade F."""
        assert _grade_ports({80, 443, 143}) == "F"

    def test_dangerous_overrides_warning(self):
        """Dangerous port present alongside warning port → F not C."""
        assert _grade_ports({80, 443, 25, 3306}) == "F"

    def test_unknown_port_grades_c(self):
        assert _grade_ports({80, 443, 9999}) == "C"

    def test_port_25_not_in_acceptable(self):
        """Port 25 must not be in ACCEPTABLE_PORTS."""
        assert 25 not in ACCEPTABLE_PORTS

    def test_port_25_in_warning(self):
        """Port 25 must be in WARNING_PORTS."""
        assert 25 in WARNING_PORTS

    def test_new_dangerous_ports_present(self):
        """FTP, Telnet, POP3, IMAP must be in DANGEROUS_PORTS."""
        assert {21, 23, 110, 143}.issubset(DANGEROUS_PORTS)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_ports.py::TestGradePorts -v`
Expected: Multiple failures — `WARNING_PORTS` doesn't exist yet, port 25 still in ACCEPTABLE_PORTS, ports 21/23/110/143 not in DANGEROUS_PORTS

- [ ] **Step 3: Update port constants in ports.py**

In `domain_audit/scanners/ports.py`:

Update `COMMON_PORTS` (add 3 new ports):

```python
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
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
```

Update port tier sets:

```python
EXPECTED_PORTS = {80, 443}
ACCEPTABLE_PORTS = {22, 8080, 8443}
WARNING_PORTS = {25}
DANGEROUS_PORTS = {21, 23, 110, 143, 1433, 3306, 3389, 5432, 9200, 9300, 27017, 27018, 27019}
```

- [ ] **Step 4: Update `_grade_ports` function**

In `domain_audit/scanners/ports.py`, replace the `_grade_ports` function:

```python
def _grade_ports(open_port_numbers: set[int]) -> str:
    if open_port_numbers & DANGEROUS_PORTS:
        return "F"
    if open_port_numbers & WARNING_PORTS:
        return "C"
    unexpected = open_port_numbers - EXPECTED_PORTS - ACCEPTABLE_PORTS - DANGEROUS_PORTS - WARNING_PORTS
    if unexpected:
        return "C"
    if open_port_numbers <= EXPECTED_PORTS:
        return "A"
    if open_port_numbers <= EXPECTED_PORTS | ACCEPTABLE_PORTS:
        return "B"
    return "A"
```

- [ ] **Step 5: Run new grading tests**

Run: `pytest tests/test_ports.py::TestGradePorts -v`
Expected: All pass

- [ ] **Step 6: Run all port tests**

Run: `pytest tests/test_ports.py -v`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add domain_audit/scanners/ports.py tests/test_ports.py
git commit -m "feat: add WARNING_PORTS tier, expand DANGEROUS_PORTS with FTP/Telnet/POP3/IMAP"
```

---

### Task 9: Add WARNING_PORTS finding and update finding text

**Files:**
- Modify: `domain_audit/scanners/ports.py` (scan function, findings)

- [ ] **Step 1: Write test for port 25 finding message**

Add to `tests/test_ports.py`:

```python
class TestPortFindings:
    @patch("domain_audit.scanners.ports._check_port")
    @patch("domain_audit.scanners.ports.socket.gethostbyname", return_value="1.2.3.4")
    def test_smtp_warning_finding(self, mock_dns, mock_check):
        def check_port(host, port):
            return port, PORT_OPEN if port in (80, 443, 25) else PORT_CLOSED

        mock_check.side_effect = check_port
        result = scan("example.com")
        assert result.grade == "C"
        # Should have a finding about SMTP
        smtp_findings = [f for f in result.findings if "SMTP" in f.get("detail", "")]
        assert len(smtp_findings) >= 1
        assert "open relay" in smtp_findings[0]["detail"].lower() or "mail server" in smtp_findings[0]["detail"].lower()

    @patch("domain_audit.scanners.ports._check_port")
    @patch("domain_audit.scanners.ports.socket.gethostbyname", return_value="1.2.3.4")
    def test_dangerous_finding_text(self, mock_dns, mock_check):
        def check_port(host, port):
            return port, PORT_OPEN if port in (80, 443, 21) else PORT_CLOSED

        mock_check.side_effect = check_port
        result = scan("example.com")
        assert result.grade == "F"
        danger_findings = [f for f in result.findings if f.get("grade") == "F"]
        assert len(danger_findings) >= 1
        assert "Dangerous service" in danger_findings[0]["detail"] or "dangerous" in danger_findings[0]["detail"].lower()
```

- [ ] **Step 2: Run to verify failures**

Run: `pytest tests/test_ports.py::TestPortFindings -v`
Expected: FAIL — no SMTP-specific finding yet, old finding text says "Database/RDP"

- [ ] **Step 3: Add WARNING_PORTS finding and update text in scan()**

In `domain_audit/scanners/ports.py`, in the `scan()` function, inside the per-host findings loop (after the dangerous ports check around line 180), add a warning ports check:

```python
        warning_open = port_nums & WARNING_PORTS
        if warning_open:
            port_names = ", ".join(f"{p} ({COMMON_PORTS[p]})" for p in sorted(warning_open))
            findings.append(
                {
                    "label": f"Warning ports — {host_label}",
                    "value": list(warning_open),
                    "grade": "C",
                    "detail": f"SMTP port open — verify this is an intended mail server, not an open relay",
                    "fix": "If this host is not a mail server, close port 25 or restrict access",
                }
            )
```

Also update the existing dangerous ports finding text (line 187):

```python
# OLD:
"detail": f"Database/RDP ports open: {port_names}",
# NEW:
"detail": f"Dangerous service ports open: {port_names}",
```

- [ ] **Step 4: Run findings tests**

Run: `pytest tests/test_ports.py::TestPortFindings -v`
Expected: All pass

- [ ] **Step 5: Run all port tests**

Run: `pytest tests/test_ports.py -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add domain_audit/scanners/ports.py tests/test_ports.py
git commit -m "feat: add SMTP warning finding, update dangerous ports finding text"
```

---

### Task 10: Add truncation logging for IP geolocation

**Files:**
- Modify: `domain_audit/scanners/dns_records.py`
- Test: `tests/test_dns_records.py`

- [ ] **Step 1: Write failing test for truncation warning**

Add to `tests/test_dns_records.py`:

```python
import logging
from unittest.mock import patch, MagicMock

from domain_audit.scanners.dns_records import _check_ips


class TestCheckIpsTruncation:
    @patch("domain_audit.scanners.dns_records.httpx")
    @patch("domain_audit.scanners.dns_records._check_port")
    @patch("domain_audit.scanners.dns_records.socket.gethostbyaddr")
    @patch("domain_audit.scanners.dns_records.is_private_ip", return_value=False)
    def test_logs_warning_when_ips_truncated(self, mock_private, mock_rdns, mock_port, mock_httpx, caplog):
        mock_rdns.side_effect = Exception("no rdns")
        mock_port.return_value = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "fail"}
        mock_httpx.get.return_value = mock_resp

        ips = [f"1.2.3.{i}" for i in range(10)]
        with caplog.at_level(logging.WARNING, logger="domain_audit.scanners.dns_records"):
            results = _check_ips(ips)

        assert len(results) == 5  # Truncated to 5
        assert "limited to 5 of 10" in caplog.text

    @patch("domain_audit.scanners.dns_records.httpx")
    @patch("domain_audit.scanners.dns_records._check_port")
    @patch("domain_audit.scanners.dns_records.socket.gethostbyaddr")
    @patch("domain_audit.scanners.dns_records.is_private_ip", return_value=False)
    def test_no_warning_when_ips_within_limit(self, mock_private, mock_rdns, mock_port, mock_httpx, caplog):
        mock_rdns.side_effect = Exception("no rdns")
        mock_port.return_value = False
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "fail"}
        mock_httpx.get.return_value = mock_resp

        ips = [f"1.2.3.{i}" for i in range(3)]
        with caplog.at_level(logging.WARNING, logger="domain_audit.scanners.dns_records"):
            results = _check_ips(ips)

        assert len(results) == 3
        assert "limited" not in caplog.text
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_dns_records.py::TestCheckIpsTruncation -v`
Expected: FAIL — no warning logged yet (and mock target may need adjusting since we already migrated to httpx)

- [ ] **Step 3: Add logging to dns_records.py**

In `domain_audit/scanners/dns_records.py`, add logger at module level (after imports):

```python
import logging

logger = logging.getLogger(__name__)
```

Then in `_check_ips()`, before the `for ip in ips[:5]:` loop:

```python
    if len(ips) > 5:
        logger.warning("IP geolocation limited to 5 of %d IPs (ip-api.com rate limit)", len(ips))
```

- [ ] **Step 4: Run truncation tests**

Run: `pytest tests/test_dns_records.py::TestCheckIpsTruncation -v`
Expected: All pass

- [ ] **Step 5: Run all dns tests**

Run: `pytest tests/test_dns_records.py -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add domain_audit/scanners/dns_records.py tests/test_dns_records.py
git commit -m "feat: log warning when IP geolocation truncates results"
```

---

### Task 11: Add truncation logging for subdomain deep scan

**Files:**
- Modify: `domain_audit/scanners/subdomains.py`
- Test: `tests/test_subdomains.py`

- [ ] **Step 1: Write failing test for truncation warning**

Add to `tests/test_subdomains.py`:

```python
import logging
from unittest.mock import patch


class TestSubdomainTruncation:
    @patch("domain_audit.scanners.subdomains._probe_subdomain")
    @patch("domain_audit.scanners.subdomains._discover_subdomains")
    def test_logs_warning_when_subdomains_truncated(self, mock_discover, mock_probe, caplog):
        # Create 30 subdomains (exceeds MAX_SUBDOMAIN_SCAN=25)
        subs = [f"sub{i}.example.com" for i in range(30)]
        mock_discover.return_value = subs
        mock_probe.return_value = {
            "subdomain": "sub0.example.com",
            "dns": {"a": ["1.2.3.4"], "aaaa": [], "cname": []},
            "ssl": {
                "has_ssl": False, "valid": False, "issuer": None,
                "expires": None, "days_left": None, "protocol": None, "error": None,
            },
            "http": {
                "reachable": False, "status_code": None, "https": False,
                "server": None, "redirect": None, "response_ms": None,
            },
        }

        with caplog.at_level(logging.WARNING, logger="domain_audit.scanners.subdomains"):
            result = scan("example.com", deep=True)

        assert "limited to 25 of 30" in caplog.text
        assert result.raw_data["total_discovered"] == 30
        assert result.raw_data["scanned_count"] == 25

    @patch("domain_audit.scanners.subdomains._probe_subdomain")
    @patch("domain_audit.scanners.subdomains._discover_subdomains")
    def test_no_warning_when_subdomains_within_limit(self, mock_discover, mock_probe, caplog):
        subs = [f"sub{i}.example.com" for i in range(5)]
        mock_discover.return_value = subs
        mock_probe.return_value = {
            "subdomain": "sub0.example.com",
            "dns": {"a": ["1.2.3.4"], "aaaa": [], "cname": []},
            "ssl": {
                "has_ssl": False, "valid": False, "issuer": None,
                "expires": None, "days_left": None, "protocol": None, "error": None,
            },
            "http": {
                "reachable": False, "status_code": None, "https": False,
                "server": None, "redirect": None, "response_ms": None,
            },
        }

        with caplog.at_level(logging.WARNING, logger="domain_audit.scanners.subdomains"):
            result = scan("example.com", deep=True)

        assert "limited" not in caplog.text
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_subdomains.py::TestSubdomainTruncation -v`
Expected: FAIL — no warning logged, no `total_discovered` in raw_data

- [ ] **Step 3: Add logging to subdomains.py**

In `domain_audit/scanners/subdomains.py`, add logger at module level (after imports):

```python
import logging

logger = logging.getLogger(__name__)
```

Then in `scan()`, around line 370 where `subs_to_scan` is set:

```python
        if deep:
            subs_to_scan = all_subs[:MAX_SUBDOMAIN_SCAN]
            raw_data["scanned_count"] = len(subs_to_scan)
            raw_data["total_discovered"] = len(all_subs)
            if len(all_subs) > MAX_SUBDOMAIN_SCAN:
                logger.warning(
                    "Deep scan limited to %d of %d subdomains",
                    MAX_SUBDOMAIN_SCAN,
                    len(all_subs),
                )
```

- [ ] **Step 4: Run truncation tests**

Run: `pytest tests/test_subdomains.py::TestSubdomainTruncation -v`
Expected: All pass

- [ ] **Step 5: Run all subdomain tests**

Run: `pytest tests/test_subdomains.py -v`
Expected: All pass

- [ ] **Step 6: Run full test suite — final verification**

Run: `pytest -v`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add domain_audit/scanners/subdomains.py tests/test_subdomains.py
git commit -m "feat: log warning when subdomain deep scan truncates results"
```
