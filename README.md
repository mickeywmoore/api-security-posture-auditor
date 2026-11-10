# SecPulse: API Security Posture Auditor & SARIF Compliance Gate

[![SecPulse CI Pipeline](https://github.com/mickeywmoore/api-security-posture-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/mickeywmoore/api-security-posture-auditor/actions/workflows/ci.yml)

A **zero-dependency** Python CLI (`secpulse`) for concurrent HTTP/API security header posture evaluation, CORS & cookie hardening verification, CI/CD score gating, and **OASIS SARIF v2.1.0** report generation.

---

## Engineering Design & Trade-Offs

1. **100% Python Standard Library (`dependencies = []`)**
   * Built exclusively on `urllib.request`, `ssl`, `concurrent.futures`, `http.server`, and `dataclasses` so CI/CD runners can install and execute compliance gates in milliseconds with zero third-party supply-chain exposure.
2. **OWASP HTTP & API Security Controls (`src/secpulse/auditor.py`)**
   * Evaluates `Strict-Transport-Security` (`max-age`), `Content-Security-Policy` (`unsafe-inline` / `unsafe-eval` / `frame-ancestors`), `X-Content-Type-Options`, anti-framing headers, wildcard CORS + credentials misconfigurations, `Set-Cookie` attributes (`Secure`, `HttpOnly`, `SameSite`), and version banner leakage.
3. **OASIS SARIF v2.1.0 & CI/CD Exit-Code Gating (`src/secpulse/sarif.py`, `cli.py`)**
   * Exports standardized SARIF v2.1.0 artifacts compatible with GitHub Code Scanning alongside `--fail-under <score>` exit-code enforcement.
4. **Deterministic Ephemeral Socket Testing (`tests/test_secpulse.py`)**
   * Spins up an in-process `ThreadingHTTPServer` bound to `127.0.0.1:0` during unit tests, verifying real TCP/HTTP wire behavior in `< 0.1s` without flaky external network calls.

---

## Repository Structure

```text
api-security-posture-auditor/
├── .github/workflows/ci.yml  # Python 3.11 & 3.12 CI test matrix
├── pyproject.toml            # Zero-dependency PEP 621 package config
├── README.md
├── src/secpulse/
│   ├── __init__.py
│   ├── auditor.py            # Concurrent HTTP/TLS policy evaluator
│   ├── cli.py                # CLI runner & --fail-under CI gatekeeper
│   ├── models.py             # Typed findings & 0-100 posture scoring
│   └── sarif.py              # OASIS SARIF v2.1.0 report serializer
└── tests/
    └── test_secpulse.py      # Ephemeral HTTP server unit & CLI tests
```

---

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Audit staging/local API endpoints and enforce a minimum posture score of 85/100
secpulse scan https://api.example.com/health --fail-under 85 --output-sarif artifacts/secpulse.sarif --output-json artifacts/posture.json

# Run deterministic ephemeral HTTP test suite
python -m unittest discover -s tests -v
```
