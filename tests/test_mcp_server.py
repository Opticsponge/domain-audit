from unittest.mock import MagicMock, patch

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

    def test_subdomains_forwarded(self):
        captured = {}

        def fake_ports(d, **kw):
            captured.update(kw)
            return _mock_scan("ports")

        with patch("domain_audit.mcp_server.SCANNERS", {"ports": fake_ports}):
            from domain_audit.mcp_server import scan_ports

            scan_ports(domain="example.com", subdomains=["api.example.com", "www.example.com"])
        assert captured["subdomains"] == ["api.example.com", "www.example.com"]


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

    def test_custom_patterns_forwarded(self):
        captured = {}

        def fake_tech(d, **kw):
            captured.update(kw)
            return _mock_scan("tech")

        patterns = {"cdn_domains": [{"pattern": "test.com", "name": "Test"}]}
        with patch("domain_audit.mcp_server.SCANNERS", {"tech": fake_tech}):
            from domain_audit.mcp_server import scan_tech

            scan_tech(domain="example.com", custom_patterns=patterns)
        assert captured["custom_patterns"] == patterns


class TestScanSubdomains:
    @patch("domain_audit.mcp_server.SCANNERS", {"subdomains": lambda d, **kw: _mock_scan("subdomains")})
    def test_returns_dict_with_expected_keys(self):
        from domain_audit.mcp_server import scan_subdomains

        result = scan_subdomains(domain="example.com")
        assert result["module"] == "subdomains"


class TestAuditDomain:
    @patch(
        "domain_audit.mcp_server.audit",
        return_value=type(
            "FakeResult",
            (),
            {
                "to_dict": lambda self: {
                    "domain": "example.com",
                    "overall_grade": "A",
                    "elapsed_seconds": 1.0,
                    "modules": {"ssl": {"module": "ssl", "grade": "A"}},
                    "action_items": [],
                }
            },
        )(),
    )
    def test_full_audit_returns_expected_structure(self, mock_audit):
        from domain_audit.mcp_server import audit_domain

        result = audit_domain(domain="example.com")
        assert result["domain"] == "example.com"
        assert result["overall_grade"] == "A"
        assert "modules" in result
        assert "action_items" in result
        mock_audit.assert_called_once_with(
            "example.com", only=None, show=False, deep_subdomains=False, tech_patterns=None
        )

    @patch(
        "domain_audit.mcp_server.audit",
        return_value=type(
            "FakeResult",
            (),
            {
                "to_dict": lambda self: {
                    "domain": "example.com",
                    "overall_grade": "A",
                    "elapsed_seconds": 1.0,
                    "modules": {"ssl": {"module": "ssl", "grade": "A"}},
                    "action_items": [],
                }
            },
        )(),
    )
    def test_scanner_filter_passed_through(self, mock_audit):
        from domain_audit.mcp_server import audit_domain

        audit_domain(domain="example.com", scanners=["ssl", "dns"])
        mock_audit.assert_called_once_with(
            "example.com", only=["ssl", "dns"], show=False, deep_subdomains=False, tech_patterns=None
        )

    @patch(
        "domain_audit.mcp_server.audit",
        return_value=type(
            "FakeResult",
            (),
            {
                "to_dict": lambda self: {
                    "domain": "example.com",
                    "overall_grade": "A",
                    "elapsed_seconds": 1.0,
                    "modules": {},
                    "action_items": [],
                }
            },
        )(),
    )
    def test_deep_flag_passed_through(self, mock_audit):
        from domain_audit.mcp_server import audit_domain

        audit_domain(domain="example.com", deep=True)
        mock_audit.assert_called_once_with(
            "example.com", only=None, show=False, deep_subdomains=True, tech_patterns=None
        )

    @patch(
        "domain_audit.mcp_server.audit",
        return_value=type(
            "FakeResult",
            (),
            {
                "to_dict": lambda self: {
                    "domain": "example.com",
                    "overall_grade": "A",
                    "elapsed_seconds": 1.0,
                    "modules": {},
                    "action_items": [],
                }
            },
        )(),
    )
    def test_tech_patterns_passed_through(self, mock_audit):
        from domain_audit.mcp_server import audit_domain

        patterns = {"cdn_domains": [{"pattern": "test.com", "name": "Test"}]}
        audit_domain(domain="example.com", tech_patterns=patterns)
        mock_audit.assert_called_once_with(
            "example.com", only=None, show=False, deep_subdomains=False, tech_patterns=patterns
        )


class TestErrorHandling:
    def test_invalid_domain_returns_error(self):
        from domain_audit.mcp_server import scan_ssl

        result = scan_ssl(domain="not a domain!!!")
        assert "error" in result
        assert result["module"] == "ssl"

    def test_empty_domain_returns_error(self):
        from domain_audit.mcp_server import scan_dns

        result = scan_dns(domain="")
        assert "error" in result

    @patch(
        "domain_audit.mcp_server.SCANNERS",
        {
            "ssl": MagicMock(side_effect=RuntimeError("connection timed out")),
        },
    )
    def test_scanner_exception_returns_error(self):
        from domain_audit.mcp_server import scan_ssl

        result = scan_ssl(domain="example.com")
        assert "error" in result
        assert "connection timed out" in result["error"]
        assert result["module"] == "ssl"

    @patch("domain_audit.mcp_server.audit", side_effect=RuntimeError("boom"))
    def test_audit_domain_exception_returns_error(self, mock_audit):
        from domain_audit.mcp_server import audit_domain

        result = audit_domain(domain="example.com")
        assert "error" in result
        assert result["domain"] == "example.com"
