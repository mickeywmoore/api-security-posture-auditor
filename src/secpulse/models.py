"""Typed data models and posture grade calculation for API security compliance."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Standardized finding severity levels mapped to score deductions and SARIF levels."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def penalty(self) -> int:
        return {"high": 25, "medium": 12, "low": 5}[self.value]

    @property
    def sarif_level(self) -> str:
        return {"high": "error", "medium": "warning", "low": "note"}[self.value]


@dataclass(frozen=True)
class AuditFinding:
    """Single security configuration finding aligned with OWASP Secure Headers guidelines."""

    rule_id: str
    title: str
    severity: Severity
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass
class EndpointPostureReport:
    """Aggregated security posture evaluation for an HTTP/API endpoint."""

    target_url: str
    status_code: int | None
    tls_version: str | None
    score: int
    grade: str
    findings: list[AuditFinding] = field(default_factory=list)
    error: str | None = None

    @staticmethod
    def compute_score_and_grade(findings: list[AuditFinding]) -> tuple[int, str]:
        raw_score = 100 - sum(f.severity.penalty for f in findings)
        score = max(0, min(100, raw_score))
        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 45:
            grade = "D"
        else:
            grade = "F"
        return score, grade

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "status_code": self.status_code,
            "tls_version": self.tls_version,
            "score": self.score,
            "grade": self.grade,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }
