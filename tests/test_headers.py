from unittest.mock import patch

from domain_audit.scanners.headers import _grade_csp, _grade_hsts, scan


class TestHeadersScan:
    @patch("domain_audit.scanners.headers._fetch_headers")
    def test_all_headers_present(self, mock_fetch):
        mock_fetch.return_value = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
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
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        result = scan("example.com")
        assert result.grade == "C"  # Missing CSP drags module to C

    @patch("domain_audit.scanners.headers._fetch_headers")
    def test_connection_error(self, mock_fetch):
        mock_fetch.side_effect = ConnectionError("failed")
        result = scan("example.com")
        assert result.status == "error"
        assert result.grade == "?"


class TestHstsGrading:
    def test_missing(self):
        result = _grade_hsts({})
        assert result["grade"] == "F"

    def test_max_age_zero(self):
        result = _grade_hsts({"strict-transport-security": "max-age=0"})
        assert result["grade"] == "F"

    def test_strong_with_subdomains(self):
        result = _grade_hsts(
            {"strict-transport-security": "max-age=31536000; includeSubDomains"}
        )
        assert result["grade"] == "A"

    def test_strong_with_preload(self):
        result = _grade_hsts(
            {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}
        )
        assert result["grade"] == "A"

    def test_strong_without_subdomains(self):
        result = _grade_hsts({"strict-transport-security": "max-age=31536000"})
        assert result["grade"] == "B"

    def test_short_max_age(self):
        result = _grade_hsts({"strict-transport-security": "max-age=3600"})
        assert result["grade"] == "C"

    def test_acceptable_max_age_without_subdomains(self):
        result = _grade_hsts({"strict-transport-security": "max-age=15768000"})
        assert result["grade"] == "B"


class TestCspGrading:
    def test_missing(self):
        result = _grade_csp({})
        assert result["grade"] == "C"

    def test_enforcing_clean(self):
        result = _grade_csp({"content-security-policy": "default-src 'self'"})
        assert result["grade"] == "A"

    def test_enforcing_with_unsafe_inline(self):
        result = _grade_csp(
            {"content-security-policy": "default-src 'self' 'unsafe-inline'"}
        )
        assert result["grade"] == "B"

    def test_enforcing_with_unsafe_eval(self):
        # CSP policy string containing the unsafe-eval directive (not actual code eval)
        result = _grade_csp(
            {"content-security-policy": "script-src 'unsafe-eval'"}
        )
        assert result["grade"] == "B"

    def test_enforcing_wildcard(self):
        result = _grade_csp({"content-security-policy": "default-src *"})
        assert result["grade"] == "C"

    def test_report_only(self):
        result = _grade_csp(
            {"content-security-policy-report-only": "default-src 'self'"}
        )
        assert result["grade"] == "B"

    def test_enforcing_takes_precedence_over_report_only(self):
        result = _grade_csp(
            {
                "content-security-policy": "default-src 'self'",
                "content-security-policy-report-only": "default-src 'self'",
            }
        )
        assert result["grade"] == "A"
