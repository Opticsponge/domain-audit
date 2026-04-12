from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class ScanResult:
    module: str
    status: str  # "pass", "warn", "fail", "error"
    grade: str  # "A", "B", "C", "F", "?", "-"
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)
    elapsed: float = 0.0
    retries: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


GRADE_VALUES = {"A": 4, "B": 3, "C": 2, "F": 0}

MODULE_WEIGHTS = {
    "ssl": 0.25,
    "dns": 0.15,
    "email": 0.15,
    "headers": 0.15,
    "whois": 0.10,
    "ports": 0.10,
    # tech and subdomains are informational — weights here for completeness only
}

# Informational modules don't contribute to overall grade
INFORMATIONAL_MODULES = {"tech", "subdomains"}


def compute_overall_grade(results: dict[str, ScanResult]) -> str:
    weighted_sum = 0.0
    total_weight = 0.0

    for module, result in results.items():
        if module in INFORMATIONAL_MODULES:
            continue
        if result.grade not in GRADE_VALUES:
            continue

        weight = MODULE_WEIGHTS.get(module, 0.0)
        weighted_sum += GRADE_VALUES[result.grade] * weight
        total_weight += weight

    if total_weight == 0:
        return "?"

    score = weighted_sum / total_weight

    if score >= 3.5:
        return "A"
    elif score >= 2.5:
        return "B"
    elif score >= 1.5:
        return "C"
    else:
        return "F"


def generate_action_items(results: dict[str, ScanResult]) -> list[dict[str, str]]:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items = []

    for module, result in results.items():
        for finding in result.findings:
            if finding.get("grade", "A") in ("A", "-"):
                continue

            severity = _grade_to_severity(finding.get("grade", "C"))
            items.append({
                "severity": severity,
                "module": module,
                "issue": finding.get("label", "Unknown issue"),
                "detail": finding.get("detail", ""),
                "fix": finding.get("fix", ""),
            })

    items.sort(key=lambda x: severity_order.get(x["severity"], 99))
    return items


def _grade_to_severity(grade: str) -> str:
    return {
        "F": "CRITICAL",
        "C": "HIGH",
        "B": "MEDIUM",
    }.get(grade, "LOW")


_GRADE_ORDER = {"F": 0, "C": 1, "B": 2, "A": 3}


def worst_grade(grades: list[str]) -> str:
    """Return the worst letter grade from a list. Ignores '?' and '-'."""
    valid = [g for g in grades if g in _GRADE_ORDER]
    if not valid:
        return "?"
    return min(valid, key=lambda g: _GRADE_ORDER[g])
