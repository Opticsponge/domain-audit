from unittest.mock import patch
from domain_audit.scanners.email_security import scan


class TestEmailSecurityScan:
    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_all_present_strict(self, mock_resolve):
        def resolver(name):
            if name.startswith("_dmarc."):
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
            elif "_domainkey" in name:
                if "google._domainkey" in name:
                    return ["v=DKIM1; k=rsa; p=MIGfMA0..."]
                return []
            else:
                return ["v=spf1 include:_spf.google.com -all"]

        mock_resolve.side_effect = resolver
        result = scan("example.com")
        assert result.grade == "A"

    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_no_records(self, mock_resolve):
        mock_resolve.return_value = []
        result = scan("example.com")
        assert result.grade == "F"

    @patch("domain_audit.scanners.email_security._resolve_txt")
    def test_spf_softfail(self, mock_resolve):
        def resolver(name):
            if name.startswith("_dmarc."):
                return ["v=DMARC1; p=reject"]
            elif "_domainkey" in name:
                return []
            else:
                return ["v=spf1 ~all"]

        mock_resolve.side_effect = resolver
        result = scan("example.com")
        # SPF=B, DMARC=A, DKIM=C -> worst is C
        assert result.grade == "C"
