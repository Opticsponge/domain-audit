from unittest.mock import patch
from domain_audit.scanners.headers import scan


class TestHeadersScan:
    @patch("domain_audit.scanners.headers._fetch_headers")
    def test_all_headers_present(self, mock_fetch):
        mock_fetch.return_value = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        result = scan("example.com")
        assert result.grade == "A"

    @patch("domain_audit.scanners.headers._fetch_headers")
    def test_no_headers(self, mock_fetch):
        mock_fetch.return_value = {"Content-Type": "text/html"}
        result = scan("example.com")
        assert result.grade == "F"

    @patch("domain_audit.scanners.headers._fetch_headers")
    def test_some_headers(self, mock_fetch):
        mock_fetch.return_value = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        result = scan("example.com")
        assert result.grade in ("B", "C")

    @patch("domain_audit.scanners.headers._fetch_headers")
    def test_connection_error(self, mock_fetch):
        mock_fetch.side_effect = ConnectionError("failed")
        result = scan("example.com")
        assert result.status == "error"
        assert result.grade == "?"
