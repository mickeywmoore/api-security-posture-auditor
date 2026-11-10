"""Zero-dependency HTTP/TLS header compliance and CORS policy evaluator."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ssl
from typing import Iterable
import urllib.error
import urllib.parse
import urllib.request

from secpulse.models import AuditFinding, EndpointPostureReport, Severity


def _evaluate_headers(
    url: str,
    headers: dict[str, str],
    set_cookies: list[str],
    is_https: bool,
) -> list[AuditFinding]:
    """Evaluate normalized HTTP response headers against OWASP API & Web security controls."""
    findings: list[AuditFinding] = []

    # 1. Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security", "")
    if is_https and not hsts:
        findings.append(
            AuditFinding(
                rule_id="SECP001",
                title="Missing Strict-Transport-Security (HSTS) header",
                severity=Severity.HIGH,
                evidence="Strict-Transport-Security header absent on HTTPS response.",
                remediation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            )
        )
    elif hsts and "max-age=" in hsts.lower():
        try:
            max_age_part = [p.strip() for p in hsts.lower().split(";") if p.strip().startswith("max-age=")][0]
            max_age = int(max_age_part.split("=", 1)[1])
            if max_age < 15_768_000:
                findings.append(
                    AuditFinding(
                        rule_id="SECP001",
                        title="Weak HSTS max-age duration",
                        severity=Severity.MEDIUM,
                        evidence=f"Strict-Transport-Security max-age={max_age} (< 6 months).",
                        remediation="Increase HSTS max-age to at least 31536000 seconds (1 year).",
                    )
                )
        except (ValueError, IndexError):
            pass

    # 2. Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append(
            AuditFinding(
                rule_id="SECP002",
                title="Missing Content-Security-Policy (CSP) header",
                severity=Severity.MEDIUM,
                evidence="Content-Security-Policy header not present.",
                remediation="Define a restrictive Content-Security-Policy (e.g., \"default-src 'none'; frame-ancestors 'none'\" for JSON APIs).",
            )
        )
    elif "'unsafe-inline'" in csp.lower() or "'unsafe-eval'" in csp.lower():
        findings.append(
            AuditFinding(
                rule_id="SECP003",
                title="Permissive CSP directive allows unsafe script execution",
                severity=Severity.MEDIUM,
                evidence=f"CSP contains unsafe token: {csp}",
                remediation="Replace 'unsafe-inline' and 'unsafe-eval' with cryptographic nonces or hashes.",
            )
        )

    # 3. X-Content-Type-Options
    xcto = headers.get("x-content-type-options", "").strip().lower()
    if xcto != "nosniff":
        findings.append(
            AuditFinding(
                rule_id="SECP004",
                title="Missing X-Content-Type-Options: nosniff",
                severity=Severity.LOW,
                evidence=f"X-Content-Type-Options='{xcto or 'missing'}'",
                remediation="Return 'X-Content-Type-Options: nosniff' on all API and static responses.",
            )
        )

    # 4. Framing protection (X-Frame-Options or CSP frame-ancestors)
    xfo = headers.get("x-frame-options", "").strip().upper()
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not has_frame_ancestors and xfo not in {"DENY", "SAMEORIGIN"}:
        findings.append(
            AuditFinding(
                rule_id="SECP005",
                title="Missing anti-framing control (Clickjacking defense)",
                severity=Severity.LOW,
                evidence="Neither CSP frame-ancestors nor X-Frame-Options (DENY/SAMEORIGIN) detected.",
                remediation="Include 'frame-ancestors 'none'' in CSP or set 'X-Frame-Options: DENY'.",
            )
        )

    # 5. CORS Policy Validation
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    if acao == "*" and acac == "true":
        findings.append(
            AuditFinding(
                rule_id="SECP006",
                title="Insecure CORS wildcard combined with credentials",
                severity=Severity.HIGH,
                evidence="Access-Control-Allow-Origin: * paired with Access-Control-Allow-Credentials: true.",
                remediation="Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins.",
            )
        )
    elif acao == "*":
        findings.append(
            AuditFinding(
                rule_id="SECP007",
                title="Unrestricted wildcard CORS policy",
                severity=Severity.LOW,
                evidence="Access-Control-Allow-Origin: *",
                remediation="Scope CORS origins to trusted front-end domains unless endpoint serves public unauthenticated data.",
            )
        )

    # 6. Cookie Attribute Hardening
    for cookie in set_cookies:
        lower_cookie = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip()
        missing_flags: list[str] = []
        if "httponly" not in lower_cookie:
            missing_flags.append("HttpOnly")
        if is_https and "secure" not in lower_cookie:
            missing_flags.append("Secure")
        if "samesite=" not in lower_cookie:
            missing_flags.append("SameSite")

        if missing_flags:
            findings.append(
                AuditFinding(
                    rule_id="SECP008",
                    title="Session/response cookie missing hardening flags",
                    severity=Severity.MEDIUM,
                    evidence=f"Cookie '{cookie_name}' missing attributes: {', '.join(missing_flags)}",
                    remediation="Append '; Secure; HttpOnly; SameSite=Strict' (or Lax) to sensitive cookies.",
                )
            )

    # 7. Server Version Banner Disclosure
    server_banner = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if any(ch.isdigit() for ch in server_banner) or powered_by:
        findings.append(
            AuditFinding(
                rule_id="SECP009",
                title="Verbose server or framework version banner disclosed",
                severity=Severity.LOW,
                evidence=f"Server='{server_banner}' X-Powered-By='{powered_by}'",
                remediation="Suppress version tokens in reverse-proxy Server headers and omit X-Powered-By.",
            )
        )

    return findings


def audit_endpoint(target_url: str, timeout: float = 5.0) -> EndpointPostureReport:
    """Perform a single non-intrusive HTTP GET compliance inspection on target_url."""
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme in '{target_url}'. Use http:// or https://.")

    is_https = parsed.scheme == "https"
    ctx = ssl.create_default_context() if is_https else None
    req = urllib.request.Request(
        target_url,
        method="GET",
        headers={"User-Agent": "SecPulse-Compliance-Auditor/1.0", "Accept": "application/json, */*"},
    )

    tls_version: str | None = None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status_code = resp.status
            raw_headers = resp.headers
            if is_https and hasattr(resp, "fp") and hasattr(resp.fp, "raw"):
                sock = getattr(resp.fp.raw, "_sock", None)
                if sock and hasattr(sock, "version"):
                    tls_version = sock.version()
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        raw_headers = exc.headers
    except Exception as exc:
        return EndpointPostureReport(
            target_url=target_url,
            status_code=None,
            tls_version=None,
            score=0,
            grade="F",
            findings=[],
            error=str(exc),
        )

    normalized_headers = {k.lower(): v for k, v in raw_headers.items()}
    set_cookies = raw_headers.get_all("Set-Cookie") or []
    findings = _evaluate_headers(target_url, normalized_headers, set_cookies, is_https=is_https)
    score, grade = EndpointPostureReport.compute_score_and_grade(findings)

    return EndpointPostureReport(
        target_url=target_url,
        status_code=status_code,
        tls_version=tls_version,
        score=score,
        grade=grade,
        findings=findings,
    )


def audit_targets_concurrently(
    urls: Iterable[str],
    max_workers: int = 4,
    timeout: float = 5.0,
) -> list[EndpointPostureReport]:
    """Audit multiple endpoints concurrently using a bounded ThreadPoolExecutor."""
    target_list = [u.strip() for u in urls if u.strip()]
    if not target_list:
        return []
    workers = max(1, min(max_workers, len(target_list)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda u: audit_endpoint(u, timeout=timeout), target_list))
