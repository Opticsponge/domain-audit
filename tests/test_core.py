from unittest.mock import patch, MagicMock
from domain_audit.core import audit, AuditResult
from domain_audit.grader import ScanResult


def _mock_scan(module, grade="A"):
    return ScanResult(
        module=module,
        status="pass",
        grade=grade,
        findings=[{"label": "test", "grade": grade, "detail": "ok", "fix": ""}],
    )


class TestAudit:
    @patch("domain_audit.core.SCANNERS", {
        "ssl": lambda d: _mock_scan("ssl", "A"),
        "dns": lambda d: _mock_scan("dns", "A"),
    })
    def test_basic_audit(self):
        result = audit("example.com", show=False)
        assert isinstance(result, AuditResult)
        assert result.domain == "example.com"
        assert result.overall_grade in ("A", "B", "C", "F", "?")
        assert "ssl" in result.results
        assert "dns" in result.results

    @patch("domain_audit.core.SCANNERS", {
        "ssl": lambda d: _mock_scan("ssl", "A"),
        "dns": lambda d: _mock_scan("dns", "A"),
        "headers": lambda d: _mock_scan("headers", "F"),
    })
    def test_only_filter(self):
        result = audit("example.com", only=["ssl"], show=False)
        assert "ssl" in result.results
        assert "dns" not in result.results
        assert "headers" not in result.results

    @patch("domain_audit.core.SCANNERS", {
        "ssl": MagicMock(side_effect=RuntimeError("boom")),
    })
    def test_scanner_crash_handled(self):
        result = audit("example.com", only=["ssl"], show=False)
        assert result.results["ssl"].status == "error"
        assert result.results["ssl"].grade == "?"

    @patch("domain_audit.core.SCANNERS", {
        "ssl": lambda d: _mock_scan("ssl", "A"),
    })
    def test_show_false_no_display(self):
        # Should not raise even without terminal/colab
        result = audit("example.com", show=False)
        assert result is not None


class TestAuditResult:
    def test_to_dict(self):
        result = AuditResult(
            domain="example.com",
            results={"ssl": _mock_scan("ssl")},
            overall_grade="A",
            action_items=[],
            elapsed=1.0,
        )
        d = result.to_dict()
        assert d["domain"] == "example.com"
        assert d["overall_grade"] == "A"
        assert "ssl" in d["modules"]

    def test_to_csv_string(self):
        result = AuditResult(
            domain="example.com",
            results={"ssl": _mock_scan("ssl")},
            overall_grade="A",
            action_items=[],
            elapsed=1.0,
        )
        csv = result.to_csv_string()
        assert "module" in csv
        assert "ssl" in csv

    def test_to_json(self, tmp_path):
        result = AuditResult(
            domain="example.com",
            results={"ssl": _mock_scan("ssl")},
            overall_grade="A",
            action_items=[],
            elapsed=1.0,
        )
        path = str(tmp_path / "out.json")
        result.to_json(path)
        import json
        with open(path) as f:
            data = json.load(f)
        assert data["domain"] == "example.com"

    def test_to_csv(self, tmp_path):
        result = AuditResult(
            domain="example.com",
            results={"ssl": _mock_scan("ssl")},
            overall_grade="A",
            action_items=[],
            elapsed=1.0,
        )
        path = str(tmp_path / "out.csv")
        result.to_csv(path)
        with open(path) as f:
            content = f.read()
        assert "ssl" in content

    def test_repr(self):
        result = AuditResult(
            domain="example.com",
            results={},
            overall_grade="B",
            action_items=[],
            elapsed=0.5,
        )
        assert "example.com" in repr(result)
        assert "B" in repr(result)
