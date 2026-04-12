from unittest.mock import patch

from domain_audit.scanners.dns_records import scan


class TestDnsScan:
    @patch("domain_audit.scanners.dns_records._check_zone_transfer")
    @patch("domain_audit.scanners.dns_records._resolve")
    def test_all_records_found(self, mock_resolve, mock_zt):
        mock_resolve.side_effect = lambda domain, rdtype: {
            "A": ["1.2.3.4"],
            "AAAA": ["::1"],
            "MX": ["10 mail.example.com"],
            "NS": ["ns1.example.com"],
            "TXT": ["v=spf1 -all"],
            "CNAME": [],
            "SOA": ["ns1.example.com admin.example.com 1 3600 600 86400 3600"],
            "SRV": [],
            "CAA": ['0 issue "letsencrypt.org"'],
        }.get(rdtype, [])
        mock_zt.return_value = {"vulnerable": False, "nameservers_tested": ["ns1.example.com"], "vulnerable_ns": []}

        result = scan("example.com")
        assert result.module == "dns"
        assert result.grade == "A"
        assert result.status == "pass"

    @patch("domain_audit.scanners.dns_records._resolve")
    def test_missing_critical_record(self, mock_resolve):
        mock_resolve.return_value = []

        result = scan("example.com")
        assert result.grade == "F"  # Missing A and NS = F

    @patch("domain_audit.scanners.dns_records._resolve")
    def test_result_structure(self, mock_resolve):
        mock_resolve.return_value = ["1.2.3.4"]

        result = scan("example.com")
        assert result.module == "dns"
        assert result.findings is not None
        assert isinstance(result.findings, list)
        assert result.elapsed >= 0
