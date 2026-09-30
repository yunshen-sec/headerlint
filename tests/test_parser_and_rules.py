from pathlib import Path

from headerlint.models import HttpResponse
from headerlint.parser import parse_sample
from headerlint.rules import audit_response


def test_parse_raw_response(tmp_path: Path):
    path = tmp_path / "response.txt"
    path.write_bytes(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Test: yes\r\n\r\nhello"
    )
    response = parse_sample(path)
    assert response.status == 200
    assert response.headers["Content-Type"] == "text/html"
    assert response.body == b"hello"


def test_parse_json_response(tmp_path: Path):
    path = tmp_path / "response.json"
    path.write_text('{"status": 204, "headers": {"X-Test": "yes"}}', encoding="utf-8")
    response = parse_sample(path)
    assert response.status == 204
    assert response.headers == {"X-Test": "yes"}


def test_rules_report_missing_and_unsafe_headers():
    response = HttpResponse(
        200,
        {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'",
            "Referrer-Policy": "unsafe-url",
        },
        "https://example.test/",
    )
    findings = audit_response(response)
    ids = {finding.rule_id for finding in findings}
    assert {"HL001", "HL004", "HL005", "HL006", "HL008", "HL009"} <= ids


def test_complete_response_passes():
    response = HttpResponse(
        200,
        {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        "https://example.test/",
    )
    assert audit_response(response) == []

