"""Deterministic ephemeral HTTP server unit & CLI integration tests for SecPulse."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

from secpulse.auditor import audit_endpoint
from secpulse.cli import main


class _MockComplianceHandler(BaseHTTPRequestHandler):
    """Local test handler serving hardened (/hardened) and unhardened (/legacy) routes."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/hardened":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Server", "gateway")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Set-Cookie", "sid=abc123; Path=/")
            self.send_header("X-Powered-By", "Express/4.18.2")
            self.end_headers()
            self.wfile.write(b'{"status":"legacy"}')

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class TestSecPulseComplianceEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockComplianceHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_hardened_endpoint_scores_perfect_a_plus(self) -> None:
        report = audit_endpoint(f"http://127.0.0.1:{self.port}/hardened")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A+")
        self.assertEqual(len(report.findings), 0)

    def test_legacy_endpoint_flags_cors_cookies_and_headers(self) -> None:
        report = audit_endpoint(f"http://127.0.0.1:{self.port}/legacy")
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("SECP002", rule_ids)  # Missing CSP
        self.assertIn("SECP006", rule_ids)  # Wildcard CORS + credentials
        self.assertIn("SECP008", rule_ids)  # Unhardened cookie flags
        self.assertIn("SECP009", rule_ids)  # Verbose X-Powered-By
        self.assertLess(report.score, 60)

    def test_cli_sarif_export_and_ci_gate_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_path = Path(tmpdir) / "results.sarif"
            json_path = Path(tmpdir) / "posture.json"

            pass_code = main(
                [
                    "scan",
                    f"http://127.0.0.1:{self.port}/hardened",
                    "--fail-under",
                    "95",
                    "--output-sarif",
                    str(sarif_path),
                    "--output-json",
                    str(json_path),
                ]
            )
            self.assertEqual(pass_code, 0)
            self.assertTrue(sarif_path.exists())
            self.assertTrue(json_path.exists())

            fail_code = main(
                [
                    "scan",
                    f"http://127.0.0.1:{self.port}/legacy",
                    "--fail-under",
                    "80",
                    "--output-sarif",
                    str(sarif_path),
                ]
            )
            self.assertEqual(fail_code, 1)
            sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertEqual(sarif_data["version"], "2.1.0")
            self.assertGreaterEqual(len(sarif_data["runs"][0]["results"]), 4)


if __name__ == "__main__":
    unittest.main()
