from unittest.mock import patch

from domain_audit.scanners.dns_records import _is_subdomain, _missing_grade, scan


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

    @patch("domain_audit.scanners.dns_records._check_zone_transfer")
    @patch("domain_audit.scanners.dns_records._resolve")
    def test_subdomain_missing_ns_not_critical(self, mock_resolve, mock_zt):
        """Subdomains inherit NS from parent zone — missing NS should not be grade F."""
        mock_resolve.side_effect = lambda domain, rdtype: {
            "A": ["1.2.3.4"],
            "NS": [],  # No NS — normal for a subdomain
            "MX": [],
            "SOA": [],
        }.get(rdtype, [])
        mock_zt.return_value = {"vulnerable": False, "nameservers_tested": [], "vulnerable_ns": []}

        result = scan("demo.example.com")
        ns_finding = next(f for f in result.findings if f["label"] == "NS records")
        assert ns_finding["grade"] == "A"  # Not F


class TestSubdomainDetection:
    def test_root_domain(self):
        assert not _is_subdomain("example.com")

    def test_subdomain(self):
        assert _is_subdomain("demo.example.com")

    def test_deep_subdomain(self):
        assert _is_subdomain("a.b.example.com")

    def test_missing_ns_grade_root(self):
        assert _missing_grade("NS", "example.com") == "F"

    def test_missing_ns_grade_subdomain(self):
        assert _missing_grade("NS", "demo.example.com") == "A"

    def test_missing_a_still_critical(self):
        assert _missing_grade("A", "demo.example.com") == "F"
