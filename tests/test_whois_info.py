from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from domain_audit.scanners.whois_info import scan


def _make_whois(days_to_expiry=365):
    w = MagicMock()
    w.registrar = "Test Registrar Inc."
    w.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
    w.expiration_date = datetime.now(tz=timezone.utc) + timedelta(days=days_to_expiry)
    w.name_servers = ["ns1.example.com", "ns2.example.com"]
    w.status = "clientTransferProhibited"
    return w


class TestWhoisScan:
    @patch("domain_audit.scanners.whois_info._whois_lookup")
    def test_healthy_domain(self, mock_lookup):
        mock_lookup.return_value = _make_whois(days_to_expiry=365)
        result = scan("example.com")
        assert result.grade == "A"

    @patch("domain_audit.scanners.whois_info._whois_lookup")
    def test_expiring_soon(self, mock_lookup):
        mock_lookup.return_value = _make_whois(days_to_expiry=60)
        result = scan("example.com")
        assert result.grade == "C"

    @patch("domain_audit.scanners.whois_info._whois_lookup")
    def test_expired_domain(self, mock_lookup):
        mock_lookup.return_value = _make_whois(days_to_expiry=-10)
        result = scan("example.com")
        assert result.grade == "F"

    @patch("domain_audit.scanners.whois_info._rdap_lookup")
    @patch("domain_audit.scanners.whois_info._whois_lookup")
    def test_lookup_failure(self, mock_lookup, mock_rdap):
        mock_lookup.side_effect = Exception("WHOIS server unreachable")
        mock_rdap.side_effect = Exception("RDAP also failed")
        result = scan("example.com")
        assert result.status == "error"
        assert result.grade == "?"
