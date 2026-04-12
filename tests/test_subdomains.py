from unittest.mock import patch, MagicMock
from domain_audit.scanners.subdomains import (
    scan,
    _discover_subdomains,
    _build_dns_table,
    _build_ssl_table,
    _build_http_table,
)


class TestDiscoverSubdomains:
    @patch("domain_audit.scanners.subdomains._query_crtsh")
    def test_basic_discovery(self, mock_crtsh):
        mock_crtsh.return_value = [
            {"name_value": "mail.example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "*.example.com"},  # Should be filtered
            {"name_value": "example.com"},
        ]
        subs = _discover_subdomains("example.com")
        assert "mail.example.com" in subs
        assert "www.example.com" in subs
        assert "example.com" in subs
        # Wildcard filtered
        assert "*.example.com" not in subs


class TestBuildTables:
    def _make_probe(self, sub="test.example.com"):
        return {
            "subdomain": sub,
            "dns": {"a": ["1.2.3.4"], "aaaa": [], "cname": []},
            "ssl": {
                "has_ssl": True, "valid": True, "issuer": "Test CA",
                "expires": "Jan 01 00:00:00 2027 GMT", "days_left": 200,
                "protocol": "TLSv1.3", "error": None,
            },
            "http": {
                "reachable": True, "status_code": 200, "https": True,
                "server": "nginx", "redirect": None, "response_ms": 120,
            },
        }

    def test_dns_table(self):
        rows = _build_dns_table([self._make_probe()])
        assert len(rows) == 1
        assert rows[0]["subdomain"] == "test.example.com"
        assert rows[0]["a_records"] == "1.2.3.4"

    def test_ssl_table(self):
        rows = _build_ssl_table([self._make_probe()])
        assert len(rows) == 1
        assert rows[0]["valid"] == "Yes"
        assert rows[0]["grade"] == "A"

    def test_ssl_table_no_ssl(self):
        probe = self._make_probe()
        probe["ssl"]["has_ssl"] = False
        rows = _build_ssl_table([probe])
        assert rows[0]["valid"] == "No SSL"

    def test_http_table_has_response_ms(self):
        rows = _build_http_table([self._make_probe()])
        assert rows[0]["response_ms"] == "120ms"

    def test_http_table_unreachable(self):
        probe = self._make_probe()
        probe["http"]["reachable"] = False
        probe["http"]["response_ms"] = None
        rows = _build_http_table([probe])
        assert rows[0]["reachable"] == "No"
        assert rows[0]["response_ms"] == "-"


class TestSubdomainScan:
    @patch("domain_audit.scanners.subdomains._probe_subdomain")
    @patch("domain_audit.scanners.subdomains._discover_subdomains")
    def test_scan_produces_tables(self, mock_discover, mock_probe):
        mock_discover.return_value = ["sub1.example.com", "sub2.example.com"]
        mock_probe.return_value = {
            "subdomain": "sub1.example.com",
            "dns": {"a": ["1.2.3.4"], "aaaa": [], "cname": []},
            "ssl": {"has_ssl": True, "valid": True, "issuer": "CA", "expires": "x", "days_left": 100, "protocol": "TLSv1.3", "error": None},
            "http": {"reachable": True, "status_code": 200, "https": True, "server": "nginx", "redirect": None, "response_ms": 50},
        }

        result = scan("example.com", deep=True)
        assert result.module == "subdomains"
        # Should have findings with table_type
        table_types = [f.get("table_type") for f in result.findings if f.get("table_type")]
        assert "dns" in table_types
        assert "ssl" in table_types
        assert "http" in table_types

    @patch("domain_audit.scanners.subdomains._discover_subdomains")
    def test_scan_shallow_no_tables(self, mock_discover):
        mock_discover.return_value = ["sub1.example.com"]
        result = scan("example.com", deep=False)
        table_types = [f.get("table_type") for f in result.findings if f.get("table_type")]
        assert table_types == []
        assert "deep=True" in result.findings[0]["detail"]

    @patch("domain_audit.scanners.subdomains._discover_subdomains")
    def test_scan_handles_ct_error(self, mock_discover):
        mock_discover.side_effect = Exception("CT log down")
        result = scan("example.com")
        assert result.status == "error"
        assert result.grade == "?"
