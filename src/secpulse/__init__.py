"""SecPulse: Zero-dependency HTTP/API security posture & SARIF compliance CLI."""

from secpulse.auditor import audit_endpoint, audit_targets_concurrently
from secpulse.models import AuditFinding, EndpointPostureReport, Severity
from secpulse.sarif import build_sarif_log

__all__ = [
    "AuditFinding",
    "EndpointPostureReport",
    "Severity",
    "audit_endpoint",
    "audit_targets_concurrently",
    "build_sarif_log",
]
__version__ = "1.0.0"
