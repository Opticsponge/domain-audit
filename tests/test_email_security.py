from unittest.mock import patch

from domain_audit.scanners.email_security import _check_dkim, _check_dmarc, _check_spf, _parse_dmarc, _parse_spf, scan


class TestParseSPF:
    def test_basic_record(self):
        rows = _parse_spf("v=spf1 include:_spf.google.com -all")
        assert len(rows) == 3
        assert rows[0]["tag"] == "v"
        assert rows[1]["tag"] == "include"
        assert rows[2]["tag"] == "all"
        assert "Fail" in rows[2]["name"]

    def test_ip4_and_mx(self):
        rows = _parse_spf("v=spf1 ip4:192.168.1.0/24 mx -all")
        tags = [r["tag"] for r in rows]
        assert "ip4" in tags
        assert "mx" in tags


class TestParseDMARC:
    def test_basic_record(self):
        rows = _parse_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
        assert len(rows) == 3
        tags = [r["tag"] for r in rows]
        assert "v" in tags
        assert "p" in tags
        assert "rua" in tags

    def test_full_record(self):
        rows = _parse_dmarc("v=DMARC1; p=quarantine; rua=mailto:a@b.com; ruf=mailto:c@d.com; fo=1; pct=100")
        assert len(rows) == 6


class TestCheckSPF:
    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_strict_spf(self, mock_resolve):
        mock_resolve.return_value = ["v=spf1 include:_spf.google.com -all"]
        result = _check_spf("example.com")
        assert result["grade"] == "A"
        assert any(t["test"] == "SPF Record Published" and t["pass"] for t in result["tests"])
        assert len(result["parsed"]) > 0

    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_no_spf(self, mock_resolve):
        mock_resolve.return_value = []
        result = _check_spf("example.com")
        assert result["grade"] == "F"
        assert not result["tests"][0]["pass"]

    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_softfail(self, mock_resolve):
        mock_resolve.return_value = ["v=spf1 ~all"]
        result = _check_spf("example.com")
        assert result["grade"] == "B"


class TestCheckDMARC:
    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_reject_policy(self, mock_resolve):
        mock_resolve.return_value = ["v=DMARC1; p=reject; rua=mailto:a@b.com"]
        result = _check_dmarc("example.com")
        assert result["grade"] == "A"
        assert len(result["parsed"]) == 3
        assert any(t["test"] == "DMARC Reporting" and t["pass"] for t in result["tests"])

    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_no_dmarc(self, mock_resolve):
        mock_resolve.return_value = []
        result = _check_dmarc("example.com")
        assert result["grade"] == "F"

    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_none_policy(self, mock_resolve):
        mock_resolve.return_value = ["v=DMARC1; p=none"]
        result = _check_dmarc("example.com")
        assert result["grade"] == "C"


class TestCheckDKIM:
    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_dkim_found(self, mock_resolve):
        def resolver(name):
            if "google._domainkey" in name:
                return ["v=DKIM1; k=rsa; p=MIGfMA0..."]
            return []

        mock_resolve.side_effect = resolver
        result = _check_dkim("example.com")
        assert result["grade"] == "A"
        assert len(result["found_selectors"]) > 0

    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_dkim_not_found(self, mock_resolve):
        mock_resolve.return_value = []
        result = _check_dkim("example.com")
        assert result["grade"] == "C"


class TestEmailScan:
    @patch("domain_audit.scanners.email_security._check_mx")
    @patch("domain_audit.scanners.email_security._resolve_txt")
    @patch("domain_audit.scanners.email_security._has_mx", return_value=True)
    def test_full_scan_structure(self, mock_has_mx, mock_resolve, mock_mx):
        def resolver(name):
            if name.startswith("_dmarc."):
                return ["v=DMARC1; p=reject; rua=mailto:a@b.com"]
            elif "_domainkey" in name:
                if "google._domainkey" in name:
                    return ["v=DKIM1; k=rsa; p=MIGfMA0..."]
                return []
            else:
                return ["v=spf1 include:_spf.google.com -all"]

        mock_resolve.side_effect = resolver
        mock_mx.return_value = {
            "mx_records": [{"priority": 10, "host": "mx.example.com"}],
            "smtp_checks": [],
            "is_free_provider": False,
            "is_disposable": False,
            "provider_name": None,
            "tests": [{"test": "MX Record Exists", "pass": True, "result": "Found 1 MX record(s)"}],
            "parsed": [],
            "grade": "A",
        }

        result = scan("example.com")
        assert result.module == "email"
        assert result.grade == "A"

        # Check findings have detailed data
        for f in result.findings:
            assert "tests" in f
            assert "parsed_record" in f
            assert "record_type" in f
            assert "domain" in f

    @patch("domain_audit.scanners.email_security._has_mx", return_value=False)
    def test_no_mx_short_circuits(self, mock_has_mx):
        """When domain has no MX records, skip SPF/DKIM/DMARC checks entirely."""
        result = scan("no-email.example.com")
        assert result.grade == "C"
        assert result.status == "warn"
        assert len(result.findings) == 1
        assert "No MX records" in result.findings[0]["detail"]

    @patch("domain_audit.scanners.email_security._has_mx", return_value=True)
    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_no_records(self, mock_resolve, mock_has_mx):
        mock_resolve.return_value = []
        result = scan("example.com")
        assert result.grade == "F"
