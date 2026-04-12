"""domain-audit: Comprehensive domain health auditing tool."""

from importlib.metadata import version, PackageNotFoundError

from domain_audit.core import audit, AuditResult
from domain_audit.grader import ScanResult
from domain_audit.scanners.tech_detect import TechPatterns

try:
    __version__ = version("domain-audit")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"

__all__ = ["audit", "AuditResult", "ScanResult", "TechPatterns", "__version__"]
