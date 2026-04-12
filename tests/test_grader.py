from domain_audit.grader import (
    ScanResult,
    compute_overall_grade,
    generate_action_items,
)


def _make_result(module: str, grade: str, findings=None) -> ScanResult:
    return ScanResult(
        module=module,
        status="pass" if grade == "A" else "warn",
        grade=grade,
        findings=findings or [],
    )


class TestComputeOverallGrade:
    def test_all_a_grades(self):
        results = {
            "ssl": _make_result("ssl", "A"),
            "dns": _make_result("dns", "A"),
            "email": _make_result("email", "A"),
            "headers": _make_result("headers", "A"),
            "whois": _make_result("whois", "A"),
            "ports": _make_result("ports", "A"),
        }
        assert compute_overall_grade(results) == "A"

    def test_mixed_grades(self):
        results = {
            "ssl": _make_result("ssl", "A"),
            "dns": _make_result("dns", "A"),
            "email": _make_result("email", "F"),
            "headers": _make_result("headers", "C"),
            "whois": _make_result("whois", "A"),
            "ports": _make_result("ports", "A"),
        }
        grade = compute_overall_grade(results)
        assert grade in ("B", "C")  # Weighted, depends on exact calculation

    def test_all_f_grades(self):
        results = {
            "ssl": _make_result("ssl", "F"),
            "dns": _make_result("dns", "F"),
            "email": _make_result("email", "F"),
            "headers": _make_result("headers", "F"),
            "whois": _make_result("whois", "F"),
            "ports": _make_result("ports", "F"),
        }
        assert compute_overall_grade(results) == "F"

    def test_informational_modules_excluded(self):
        results = {
            "ssl": _make_result("ssl", "A"),
            "dns": _make_result("dns", "A"),
            "email": _make_result("email", "A"),
            "headers": _make_result("headers", "A"),
            "whois": _make_result("whois", "A"),
            "ports": _make_result("ports", "A"),
            "tech": _make_result("tech", "F"),  # Informational, should be ignored
            "subdomains": _make_result("subdomains", "F"),  # Informational
        }
        assert compute_overall_grade(results) == "A"

    def test_empty_results(self):
        assert compute_overall_grade({}) == "?"

    def test_unknown_grades_skipped(self):
        results = {
            "ssl": _make_result("ssl", "?"),
            "dns": _make_result("dns", "A"),
        }
        # Only dns contributes
        assert compute_overall_grade(results) == "A"


class TestGenerateActionItems:
    def test_no_items_for_all_a(self):
        results = {
            "ssl": _make_result(
                "ssl",
                "A",
                findings=[
                    {"label": "Cert valid", "grade": "A", "detail": "Good", "fix": ""},
                ],
            ),
        }
        items = generate_action_items(results)
        assert items == []

    def test_generates_items_for_failures(self):
        results = {
            "email": _make_result(
                "email",
                "F",
                findings=[
                    {"label": "SPF record", "grade": "F", "detail": "Missing", "fix": "Add SPF"},
                    {"label": "DMARC", "grade": "F", "detail": "Missing", "fix": "Add DMARC"},
                ],
            ),
        }
        items = generate_action_items(results)
        assert len(items) == 2
        assert items[0]["severity"] == "CRITICAL"
        assert items[0]["module"] == "email"

    def test_sorted_by_severity(self):
        results = {
            "headers": _make_result(
                "headers",
                "C",
                findings=[
                    {"label": "CSP", "grade": "C", "detail": "Missing", "fix": "Add CSP"},
                ],
            ),
            "ssl": _make_result(
                "ssl",
                "F",
                findings=[
                    {"label": "Expired", "grade": "F", "detail": "Expired", "fix": "Renew"},
                ],
            ),
        }
        items = generate_action_items(results)
        assert items[0]["severity"] == "CRITICAL"
        assert items[1]["severity"] == "HIGH"

    def test_location_from_domain_field(self):
        results = {
            "headers": _make_result(
                "headers",
                "C",
                findings=[
                    {"label": "CSP", "grade": "C", "detail": "Missing", "fix": "Add CSP", "domain": "sub.example.com"},
                ],
            ),
        }
        items = generate_action_items(results)
        assert items[0]["location"] == "sub.example.com"

    def test_location_from_host_field(self):
        results = {
            "ports": _make_result(
                "ports",
                "F",
                findings=[
                    {
                        "label": "Dangerous ports",
                        "grade": "F",
                        "detail": "3306 open",
                        "fix": "Close port",
                        "host": "db.example.com",
                    },
                ],
            ),
        }
        items = generate_action_items(results)
        assert items[0]["location"] == "db.example.com"

    def test_no_location_when_absent(self):
        results = {
            "ssl": _make_result(
                "ssl",
                "F",
                findings=[
                    {"label": "Expired", "grade": "F", "detail": "Expired", "fix": "Renew"},
                ],
            ),
        }
        items = generate_action_items(results)
        assert "location" not in items[0]
