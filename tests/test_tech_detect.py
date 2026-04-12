from unittest.mock import patch
from domain_audit.scanners.tech_detect import scan


class TestTechDetectScan:
    @patch("domain_audit.scanners.tech_detect._fetch_page")
    def test_detects_server_header(self, mock_fetch):
        mock_fetch.return_value = (
            {"Server": "nginx/1.20", "Content-Type": "text/html"},
            "<html><body>Hello</body></html>",
        )
        result = scan("example.com")
        assert result.grade == "-"
        techs = result.raw_data.get("technologies", [])
        assert any(t["name"] == "nginx" for t in techs)

    @patch("domain_audit.scanners.tech_detect._fetch_page")
    def test_detects_wordpress(self, mock_fetch):
        mock_fetch.return_value = (
            {"Content-Type": "text/html"},
            '<html><meta name="generator" content="WordPress 6.0"><a href="/wp-admin/">Admin</a></html>',
        )
        result = scan("example.com")
        techs = result.raw_data.get("technologies", [])
        assert any("WordPress" in t["name"] for t in techs)

    @patch("domain_audit.scanners.tech_detect._fetch_page")
    def test_no_techs_detected(self, mock_fetch):
        mock_fetch.return_value = (
            {"Content-Type": "text/html"},
            "<html><body>Minimal page</body></html>",
        )
        result = scan("example.com")
        assert result.grade == "-"

    @patch("domain_audit.scanners.tech_detect._fetch_page")
    def test_fetch_error(self, mock_fetch):
        mock_fetch.side_effect = ConnectionError("timeout")
        result = scan("example.com")
        assert result.status == "error"
