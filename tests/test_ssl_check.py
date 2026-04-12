from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from domain_audit.scanners.ssl_check import scan


def _make_cert(days_left=100, cn="example.com"):
    expiry = datetime.now(tz=timezone.utc) + timedelta(days=days_left)
    not_after = expiry.strftime("%b %d %H:%M:%S %Y GMT")
    return {
        "cert": {
            "notAfter": not_after,
            "issuer": [[("organizationName", "Test CA")]],
            "subjectAltName": [("DNS", cn), ("DNS", f"*.{cn}")],
        },
        "protocol": "TLSv1.3",
    }


class TestSslScan:
    @patch("domain_audit.scanners.ssl_check._get_cert")
    def test_valid_cert_grade_a(self, mock_get_cert):
        mock_get_cert.return_value = _make_cert(days_left=100)
        result = scan("example.com")
        assert result.grade == "A"

    @patch("domain_audit.scanners.ssl_check._get_cert")
    def test_expiring_soon_grade_b(self, mock_get_cert):
        mock_get_cert.return_value = _make_cert(days_left=60)
        result = scan("example.com")
        assert result.grade == "B"

    @patch("domain_audit.scanners.ssl_check._get_cert")
    def test_expiring_very_soon_grade_c(self, mock_get_cert):
        mock_get_cert.return_value = _make_cert(days_left=15)
        result = scan("example.com")
        assert result.grade == "C"

    @patch("domain_audit.scanners.ssl_check._get_cert")
    def test_expired_grade_f(self, mock_get_cert):
        mock_get_cert.return_value = _make_cert(days_left=-5)
        result = scan("example.com")
        assert result.grade == "F"

    @patch("domain_audit.scanners.ssl_check._get_cert")
    def test_connection_failure(self, mock_get_cert):
        mock_get_cert.side_effect = ConnectionRefusedError("refused")
        result = scan("example.com")
        assert result.status == "error"
        assert result.grade == "?"
