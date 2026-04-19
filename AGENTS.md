# AGENTS.md

## Identity

- **Name:** domain-audit
- **Read-only:** Yes. Cannot modify DNS, certificates, or any remote state.
- **API keys required:** None.

## Non-Obvious Constraints

- Rate-limited internally: 10 req/s global, 2 req/s per host. Bursts above this will queue, not fail.
- Per-scanner timeouts: 3–15s. Retries use exponential backoff with jitter (max 3 retries).
- WHOIS data varies by registrar and TLD. Some fields may be redacted or missing entirely.

## Grade Weights

SSL 25%, DNS 15%, Email 15%, Headers 15%, WHOIS 10%, Ports 10%. Subdomains and Tech are informational (ungraded).

## Integration Notes

Three interfaces available. See [README](README.md) for full docs, scanner list, and examples.

### MCP

Error shape (not in tool schemas): `{"error": string, "module": string}`.

### Python API

```python
from domain_audit import audit
result = audit("example.com", show=False)  # show defaults to True — set False for agent use
data = result.to_dict()
```

`show=False` suppresses terminal output. Without it, Rich console rendering pollutes stdout.

### CLI

```bash
domain-audit example.com --format json
```

`--format json` writes to stdout. Add `-o file.json` to write to file instead. Exit code 0 on success.
