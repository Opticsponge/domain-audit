from unittest.mock import patch

from domain_audit.scanners.ports import PORT_CLOSED, PORT_OPEN, _grade_ports, scan


class TestPortsScan:
    @patch("domain_audit.scanners.ports._check_port")
    @patch("domain_audit.scanners.ports.socket.gethostbyname", return_value="1.2.3.4")
    def test_only_web_ports(self, mock_dns, mock_check):
        def check_port(domain, port):
            return port, PORT_OPEN if port in (80, 443) else PORT_CLOSED

        mock_check.side_effect = check_port
        result = scan("example.com")
        assert result.grade == "A"

    @patch("domain_audit.scanners.ports._check_port")
    @patch("domain_audit.scanners.ports.socket.gethostbyname", return_value="1.2.3.4")
    def test_dangerous_port_open(self, mock_dns, mock_check):
        def check_port(domain, port):
            return port, PORT_OPEN if port in (80, 443, 3306) else PORT_CLOSED

        mock_check.side_effect = check_port
        result = scan("example.com")
        assert result.grade == "F"

    @patch("domain_audit.scanners.ports._check_port")
    @patch("domain_audit.scanners.ports.socket.gethostbyname", return_value="1.2.3.4")
    def test_smtp_warning_port(self, mock_dns, mock_check):
        def check_port(domain, port):
            return port, PORT_OPEN if port in (80, 443, 25) else PORT_CLOSED

        mock_check.side_effect = check_port
        result = scan("example.com")
        assert result.grade == "C"
        warning_findings = [f for f in result.findings if "Warning" in f["label"]]
        assert len(warning_findings) == 1
        assert "SMTP" in warning_findings[0]["detail"]

    @patch("domain_audit.scanners.ports.socket.gethostbyname")
    def test_dns_failure(self, mock_dns):
        import socket

        mock_dns.side_effect = socket.gaierror("no resolution")
        result = scan("nonexistent.invalid")
        assert result.status == "error"
        assert result.grade == "?"


class TestGradePorts:
    def test_expected_only(self):
        assert _grade_ports({80, 443}) == "A"

    def test_empty(self):
        assert _grade_ports(set()) == "A"

    def test_acceptable(self):
        assert _grade_ports({80, 443, 22}) == "B"

    def test_warning_port_25(self):
        assert _grade_ports({80, 443, 25}) == "C"

    def test_dangerous_cleartext(self):
        assert _grade_ports({80, 443, 21}) == "F"
        assert _grade_ports({80, 443, 23}) == "F"
        assert _grade_ports({80, 443, 110}) == "F"
        assert _grade_ports({80, 443, 143}) == "F"

    def test_dangerous_database(self):
        assert _grade_ports({80, 443, 3306}) == "F"
        assert _grade_ports({80, 443, 5432}) == "F"
        assert _grade_ports({80, 443, 27017}) == "F"

    def test_dangerous_beats_warning(self):
        assert _grade_ports({80, 443, 25, 3306}) == "F"
