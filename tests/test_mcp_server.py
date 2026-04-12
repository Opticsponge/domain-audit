from unittest.mock import patch

from domain_audit.grader import ScanResult
from domain_audit.mcp_server import list_scanners


class TestListScanners:
    def test_returns_all_scanner_names(self):
        result = list_scanners()
        names = [s["name"] for s in result["scanners"]]
        assert "ssl" in names
        assert "dns" in names
        assert "headers" in names
        assert "whois" in names
        assert "ports" in names
        assert "email" in names
        assert "tech" in names
        assert "subdomains" in names
        assert len(result["scanners"]) == 8

    def test_each_scanner_has_description(self):
        result = list_scanners()
        for scanner in result["scanners"]:
            assert "name" in scanner
            assert "description" in scanner
            assert len(scanner["description"]) > 0


def _mock_scan(module, grade="A"):
    return ScanResult(
        module=module,
        status="pass",
        grade=grade,
        findings=[{"label": "test", "grade": grade, "detail": "ok", "fix": ""}],
        raw_data={"test": True},
    )


class TestScanDns:
    @patch("domain_audit.mcp_server.SCANNERS", {"dns": lambda d: _mock_scan("dns")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_dns
        result = scan_dns(domain="example.com")
        assert result["module"] == "dns"
        assert result["grade"] == "A"
        assert result["status"] == "pass"
        assert "findings" in result
        assert "raw_data" in result


class TestScanSsl:
    @patch("domain_audit.mcp_server.SCANNERS", {"ssl": lambda d: _mock_scan("ssl")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_ssl
        result = scan_ssl(domain="example.com")
        assert result["module"] == "ssl"
        assert result["grade"] == "A"


class TestScanHeaders:
    @patch("domain_audit.mcp_server.SCANNERS", {"headers": lambda d: _mock_scan("headers")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_headers
        result = scan_headers(domain="example.com")
        assert result["module"] == "headers"


class TestScanWhois:
    @patch("domain_audit.mcp_server.SCANNERS", {"whois": lambda d: _mock_scan("whois")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_whois
        result = scan_whois(domain="example.com")
        assert result["module"] == "whois"


class TestScanPorts:
    @patch("domain_audit.mcp_server.SCANNERS", {"ports": lambda d, **kw: _mock_scan("ports")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_ports
        result = scan_ports(domain="example.com")
        assert result["module"] == "ports"


class TestScanEmail:
    @patch("domain_audit.mcp_server.SCANNERS", {"email": lambda d: _mock_scan("email")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_email
        result = scan_email(domain="example.com")
        assert result["module"] == "email"


class TestScanTech:
    @patch("domain_audit.mcp_server.SCANNERS", {"tech": lambda d, **kw: _mock_scan("tech")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_tech
        result = scan_tech(domain="example.com")
        assert result["module"] == "tech"


class TestScanSubdomains:
    @patch("domain_audit.mcp_server.SCANNERS", {"subdomains": lambda d, **kw: _mock_scan("subdomains")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_subdomains
        result = scan_subdomains(domain="example.com")
        assert result["module"] == "subdomains"
