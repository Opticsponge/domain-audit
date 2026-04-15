# Cleanup & Port Tier Restructure

**Date:** 2026-04-14
**Status:** Approved

Two-phase change set: Phase 1 is pure refactoring (no behavior change), Phase 2 introduces new port grading tiers and logging improvements.

---

## Phase 1: Refactoring

### 1. Replace `requests` with `httpx` (sync)

**Why:** `requests` has poor async support. `httpx` is the modern replacement with an almost identical sync API, and provides a migration path to async later.

**Files:**

| File | Change |
|------|--------|
| `domain_audit/scanners/headers.py:6` | `import requests` → `import httpx` |
| `domain_audit/scanners/subdomains.py:13` | Same, plus all `requests.get()` → `httpx.get()` |
| `domain_audit/scanners/tech_detect.py:15` | Same |
| `domain_audit/scanners/dns_records.py:120` | Inline `import requests` → `import httpx` inside `_check_ips()` |
| `pyproject.toml` | `"requests>=2.28"` → `"httpx>=0.27"` |

**API differences to handle:**
- `httpx` does not follow redirects by default. Add `follow_redirects=True` where needed.
- Exception hierarchy: `requests.RequestException` → `httpx.RequestError`. `requests.exceptions.HTTPError` → `httpx.HTTPStatusError`.
- `resp.json()`, `resp.status_code`, `resp.text`, `resp.headers` — identical.
- Timeout parameter — identical (`timeout=5.0`).

### 2. Deduplicate DANGEROUS_PORTS

**Problem:** `DANGEROUS_PORTS` is defined in two places with divergent contents:
- `domain_audit/scanners/ports.py:33` — 9 ports (canonical)
- `domain_audit/scanners/dns_records.py:94-101` — 6 ports (missing 9300, 27018, 27019)

**Fix:** Delete the dict in `dns_records.py`. Import from `ports.py`:

```python
from domain_audit.scanners.ports import COMMON_PORTS, DANGEROUS_PORTS
```

The `_check_port` loop in `dns_records.py:163` iterates `DANGEROUS_PORTS.items()`, which requires the dict form. Since `ports.py` defines `DANGEROUS_PORTS` as a set and `COMMON_PORTS` as a dict, the dns_records code will iterate `COMMON_PORTS` filtered by `DANGEROUS_PORTS` membership:

```python
for port in DANGEROUS_PORTS:
    service = COMMON_PORTS.get(port, "unknown")
    if _check_port(ip, port):
        open_dangerous.append({"port": port, "service": service})
```

### 3. Deduplicate port grading logic

**Problem:** `report_tables.py:22-32` (`_grade_host_ports`) is a copy-paste of `ports.py:96-107` (`_grade_ports`). Both functions are identical.

**Fix:** Delete `_grade_host_ports()` from `report_tables.py`. Import `_grade_ports` from `ports.py`:

```python
from domain_audit.scanners.ports import _grade_ports
```

Replace all calls to `_grade_host_ports(...)` with `_grade_ports(...)`.

### 4. Extract Colab code to `domain_audit/colab.py`

**Problem:** Colab-specific code is mixed into `core.py` and `report.py`, making both files longer and harder to maintain. The `_is_colab()` detection function is duplicated.

**New module:** `domain_audit/colab.py`

**What moves:**

| From | Function | To |
|------|----------|----|
| `core.py:99-105` | `_is_colab()` | `colab.py:is_colab()` |
| `report.py:70-76` | `_is_colab()` (duplicate) | Deleted, use `colab.py:is_colab()` |
| `core.py:108-188` | `_make_progress_colab()` | `colab.py:make_progress_colab()` |
| `report.py:358-433` | `_colab_data_table()` | `colab.py:colab_data_table()` |
| `report.py:436-596+` | `_display_colab()` | `colab.py:display_colab()` |

**Callers updated:**
- `core.py` imports `is_colab`, `make_progress_colab` from `colab`
- `report.py` imports `is_colab`, `display_colab` from `colab`

The progress widget is already a callback factory (`make_progress_colab` returns a `Callable`), so `core.py` just calls the returned callback — no interface change.

The Colab report renderer references `_esc`, `GRADE_COLORS_HTML`, `GRADE_LABEL_HTML`, `MODULE_LABELS`, `MODULE_ORDER` from `report.py`. These constants stay in `report.py` (they're general-purpose, not Colab-specific). `colab.py` imports them from `report.py` at module level. `report.py` avoids circular imports by using a lazy import for `colab.py` inside the `display()` function body — this matches the existing codebase pattern where `rich` and `IPython` are imported inside functions.

### 5. Bump `rich` upper cap

**Change:** `"rich>=12.4,<14"` → `"rich>=12.4,<15"` in `pyproject.toml`.

**Why:** Rich v14 has no breaking changes for the Console/Table/Columns API used by this project. The `<14` cap was preemptive and will block upgrades unnecessarily.

### 6. Fix README badge

**Change:** In `README.md`, update the Python version badge from `python-3.9+-blue` to `python-3.10+-blue`.

**Why:** `pyproject.toml` specifies `requires-python = ">=3.10"`. The badge is wrong.

---

## Phase 2: Behavior Changes

### 7. New WARNING_PORTS tier

**Problem:** Port 25 (SMTP) is in `ACCEPTABLE_PORTS`, which gives a B grade. On a web domain's primary IP, open SMTP is a misconfiguration risk or potential open relay. But a blanket F is too harsh since some orgs colocate web + mail.

**Fix:** New tier in `ports.py`:

```python
ACCEPTABLE_PORTS = {22, 8080, 8443}       # Port 25 removed
WARNING_PORTS = {25}                        # New tier — grade C
```

Updated `_grade_ports()`:

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

A specific finding is generated when port 25 is open:
> "SMTP port open — verify this is an intended mail server, not an open relay"

**report_tables.py** updated to import `WARNING_PORTS` (needed for the grading function, which it now imports directly per item 3).

### 8. Expand DANGEROUS_PORTS

**New ports added to DANGEROUS_PORTS:**

| Port | Service | Why dangerous |
|------|---------|---------------|
| 21 | FTP | Cleartext credentials |
| 23 | Telnet | Cleartext everything |
| 110 | POP3 | Cleartext mail retrieval (use 995/POP3S) |
| 143 | IMAP | Cleartext mail access (use 993/IMAPS) |

**Updated constants:**

```python
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",         # NEW
    25: "SMTP",
    80: "HTTP",
    110: "POP3",          # NEW
    143: "IMAP",          # NEW
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

DANGEROUS_PORTS = {21, 23, 110, 143, 1433, 3306, 3389, 5432, 9200, 9300, 27017, 27018, 27019}
```

**SSH (22) stays in ACCEPTABLE_PORTS.** Hardened SSH with key auth is standard practice. Flagging every server with SSH would generate noise.

**Finding text update:** `ports.py:187` currently says "Database/RDP ports open". Change to "Dangerous service ports open" since the set now includes cleartext protocols.

### 9. Log truncation warnings

**Problem:** Two places silently truncate lists without informing the user.

**Fix 1 — IP geolocation** (`dns_records.py:125`):

```python
import logging
logger = logging.getLogger(__name__)

if len(ips) > 5:
    logger.warning("IP geolocation limited to 5 of %d IPs (ip-api.com rate limit)", len(ips))
```

Also add to `raw_data`:
```python
raw_data["ip_info_total"] = len(ips)
raw_data["ip_info_scanned"] = min(len(ips), 5)
```

**Fix 2 — Subdomain deep scan** (`subdomains.py:370`):

```python
if len(all_subs) > MAX_SUBDOMAIN_SCAN:
    logger.warning("Deep scan limited to %d of %d subdomains", MAX_SUBDOMAIN_SCAN, len(all_subs))
```

`raw_data["scanned_count"]` already exists at line 371. Add `raw_data["total_discovered"]` = `len(all_subs)` alongside it.

---

## What's NOT changing

- **`py.typed`** — Correct PEP 561 marker, stays as-is.
- **Python version** — Stays at `>=3.10`. Only the README badge text is fixed.
- **Orchestration** — `ThreadPoolExecutor` in `core.py` stays. httpx swap is sync-only.
- **SSH (port 22)** — Stays in ACCEPTABLE_PORTS (grade B).

## Testing

- Existing test suite should pass after Phase 1 with no behavior changes.
- Phase 2 requires updating port-related tests for new tiers and expanded DANGEROUS_PORTS.
- New test cases needed for:
  - `WARNING_PORTS` grading (port 25 open → grade C)
  - Expanded `DANGEROUS_PORTS` (ports 21, 23, 110, 143 open → grade F)
  - Truncation logging (mock logger, verify warning emitted)
