"""CLI entry point for SecPulse security header compliance & SARIF gatekeeping."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secpulse import __version__
from secpulse.auditor import audit_targets_concurrently
from secpulse.sarif import build_sarif_log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secpulse",
        description="Zero-dependency HTTP/API security header posture auditor & SARIF CI gatekeeper.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_cmd = subparsers.add_parser(
        "scan",
        help="Audit one or more HTTP/HTTPS endpoints and compute security posture scores.",
    )
    scan_cmd.add_argument(
        "urls",
        nargs="*",
        help="One or more target URLs (http:// or https://) to audit.",
    )
    scan_cmd.add_argument(
        "--targets-file",
        type=str,
        default="",
        help="Optional newline-delimited file of target URLs.",
    )
    scan_cmd.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Maximum concurrent worker threads (default: 4).",
    )
    scan_cmd.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-request socket timeout in seconds (default: 5.0).",
    )
    scan_cmd.add_argument(
        "--fail-under",
        type=int,
        default=0,
        help="Minimum acceptable posture score (0-100) before exiting non-zero for CI/CD gating.",
    )
    scan_cmd.add_argument(
        "--output-json",
        type=str,
        default="",
        help="Optional path to export structured JSON posture telemetry.",
    )
    scan_cmd.add_argument(
        "--output-sarif",
        type=str,
        default="",
        help="Optional path to export OASIS SARIF v2.1.0 report for GitHub Code Scanning.",
    )
    return parser


def run_scan(args: argparse.Namespace) -> int:
    targets: list[str] = list(args.urls)
    if args.targets_file:
        lines = Path(args.targets_file).read_text(encoding="utf-8").splitlines()
        targets.extend(line.strip() for line in lines if line.strip() and not line.strip().startswith("#"))

    if not targets:
        print("Error: Provide at least one URL or --targets-file.")
        return 2

    reports = audit_targets_concurrently(targets, max_workers=args.workers, timeout=args.timeout)

    print("=== SecPulse API Security Posture Report ===")
    for rep in reports:
        if rep.error:
            print(f"\n[ERROR] {rep.target_url} -> Connection failed: {rep.error}")
            continue
        print(
            f"\nTarget : {rep.target_url} | HTTP {rep.status_code} | Score: {rep.score}/100 (Grade: {rep.grade})"
        )
        if not rep.findings:
            print("  [PASS] All evaluated OWASP HTTP security controls satisfied.")
        for f in rep.findings:
            print(f"  [{f.severity.value.upper():6s}] {f.rule_id}: {f.title}")
            print(f"           Evidence : {f.evidence}")
            print(f"           Fix      : {f.remediation}")

    if args.output_json:
        out_json = Path(args.output_json)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "tool": "secpulse",
            "version": __version__,
            "endpoints_scanned": len(reports),
            "minimum_score": min((r.score for r in reports), default=0),
            "reports": [r.to_dict() for r in reports],
        }
        out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nSaved JSON posture report -> {out_json}")

    if args.output_sarif:
        out_sarif = Path(args.output_sarif)
        out_sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif_doc = build_sarif_log(reports, tool_version=__version__)
        out_sarif.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        print(f"Saved SARIF v2.1.0 report -> {out_sarif}")

    min_score = min((r.score for r in reports), default=0)
    if args.fail_under > 0 and min_score < args.fail_under:
        print(
            f"\n[CI GATE FAILED] Minimum posture score {min_score} fell below --fail-under {args.fail_under}."
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
