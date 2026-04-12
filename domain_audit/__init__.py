"""domain-audit: Comprehensive domain health auditing tool."""

from domain_audit.core import audit, AuditResult
from domain_audit.grader import ScanResult

__version__ = "0.1.0"
__all__ = ["audit", "AuditResult", "ScanResult"]
