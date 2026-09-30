"""Deterministic checks for commonly deployed browser security headers."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Finding, HttpResponse


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    message: str,
    remediation: str,
    header: str | None = None,
) -> Finding:
    return Finding(rule_id, severity, title, message, remediation, header)


def audit_response(response: HttpResponse) -> list[Finding]:
    """Return findings for *response* in stable rule order.

    A missing header is a warning because applicability depends on the endpoint. A
    present but unsafe value is an error. This intentionally reports actionable
    issues without trying to prove that an application is secure.
    """

    headers = {key.lower(): value.strip() for key, value in response.headers.items()}
    findings: list[Finding] = []

    if response.url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            _finding(
                "HL001",
                "warning",
                "HSTS is missing",
                "HTTPS responses should send Strict-Transport-Security.",
                "Set Strict-Transport-Security with an appropriate max-age and review includeSubDomains/preload before enabling them.",
                "Strict-Transport-Security",
            )
        )
    elif "strict-transport-security" in headers:
        value = headers["strict-transport-security"]
        if "max-age=" not in value.lower():
            findings.append(
                _finding(
                    "HL002",
                    "error",
                    "HSTS has no max-age",
                    "Strict-Transport-Security is present but does not contain max-age.",
                    "Add a positive max-age value after confirming every subresource is HTTPS.",
                    "Strict-Transport-Security",
                )
            )

    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(
            _finding(
                "HL003",
                "warning",
                "Content Security Policy is missing",
                "The response does not declare a Content-Security-Policy.",
                "Define a policy appropriate for the application and deploy it using report-only mode first if needed.",
                "Content-Security-Policy",
            )
        )
    elif "unsafe-eval" in csp.lower():
        findings.append(
            _finding(
                "HL004",
                "error",
                "CSP permits unsafe-eval",
                "Content-Security-Policy contains unsafe-eval, which weakens script isolation.",
                "Remove unsafe-eval and update code or dependencies that require dynamic evaluation.",
                "Content-Security-Policy",
            )
        )

    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            _finding(
                "HL005",
                "warning",
                "MIME sniffing protection is missing",
                "X-Content-Type-Options is absent or is not set to nosniff.",
                "Send X-Content-Type-Options: nosniff.",
                "X-Content-Type-Options",
            )
        )

    has_frame_protection = "x-frame-options" in headers or (
        csp is not None and "frame-ancestors" in csp.lower()
    )
    if not has_frame_protection:
        findings.append(
            _finding(
                "HL006",
                "warning",
                "Clickjacking protection is missing",
                "Neither X-Frame-Options nor CSP frame-ancestors is present.",
                "Set X-Frame-Options or preferably a CSP frame-ancestors directive based on the embedding policy.",
                "X-Frame-Options",
            )
        )

    referrer = headers.get("referrer-policy", "")
    if not referrer:
        findings.append(
            _finding(
                "HL007",
                "warning",
                "Referrer Policy is missing",
                "The response does not constrain the Referer header.",
                "Send Referrer-Policy: strict-origin-when-cross-origin or a stricter policy.",
                "Referrer-Policy",
            )
        )
    elif referrer.lower().strip() == "unsafe-url":
        findings.append(
            _finding(
                "HL008",
                "error",
                "Referrer Policy exposes full URLs",
                "Referrer-Policy: unsafe-url can disclose paths and query strings cross-origin.",
                "Use strict-origin-when-cross-origin, no-referrer, or another policy matching the application need.",
                "Referrer-Policy",
            )
        )

    if "permissions-policy" not in headers:
        findings.append(
            _finding(
                "HL009",
                "warning",
                "Permissions Policy is missing",
                "The response does not limit powerful browser features.",
                "Send Permissions-Policy and explicitly disable features the application does not need.",
                "Permissions-Policy",
            )
        )

    return findings


def rule_ids(findings: Iterable[Finding]) -> set[str]:
    return {finding.rule_id for finding in findings}

