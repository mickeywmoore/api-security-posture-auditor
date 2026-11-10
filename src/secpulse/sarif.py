"""OASIS SARIF v2.1.0 report serializer for GitHub Code Scanning & CI/CD pipelines."""

from __future__ import annotations

from typing import Any
from secpulse.models import EndpointPostureReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def build_sarif_log(reports: list[EndpointPostureReport], tool_version: str = "1.0.0") -> dict[str, Any]:
    """Serialize endpoint posture findings into a valid OASIS SARIF v2.1.0 JSON structure."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for report in reports:
        for finding in report.findings:
            if finding.rule_id not in rules_by_id:
                rules_by_id[finding.rule_id] = {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.title},
                    "help": {"text": finding.remediation},
                    "defaultConfiguration": {"level": finding.severity.sarif_level},
                }

            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": finding.severity.sarif_level,
                    "message": {
                        "text": f"{finding.title} | Evidence: {finding.evidence} | Fix: {finding.remediation}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": report.target_url}
                            }
                        }
                    ],
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecPulse",
                        "version": tool_version,
                        "informationUri": "https://github.com/mickeywmoore/api-security-posture-auditor",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
