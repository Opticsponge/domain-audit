from unittest.mock import patch
from domain_audit.scanners.ports import scan


class TestPortsScan:
    @patch("domain_audit.scanners.ports._check_port")
    @patch("domain_audit.scanners.ports.socket.gethostbyname", return_value="1.2.3.4")
    def test_only_web_ports(self, mock_dns, mock_check):
        def check_port(domain, port):
            return port, port in (80, 443)

        mock_check.side_effect = check_port
        result = scan("example.com")
        assert result.grade == "A"

    @patch("domain_audit.scanners.ports._check_port")
    @patch("domain_audit.scanners.ports.socket.gethostbyname", return_value="1.2.3.4")
    def test_dangerous_port_open(self, mock_dns, mock_check):
        def check_port(domain, port):
            return port, port in (80, 443, 3306)

        mock_check.side_effect = check_port
        result = scan("example.com")
        assert result.grade == "F"

    @patch("domain_audit.scanners.ports.socket.gethostbyname")
    def test_dns_failure(self, mock_dns):
        import socket
        mock_dns.side_effect = socket.gaierror("no resolution")
        result = scan("nonexistent.invalid")
        assert result.status == "error"
        assert result.grade == "?"
