"""Render audit reports for terminals and CI systems."""

from __future__ import annotations

import json
from typing import Any

from .models import AuditReport, Finding


def render_table(report: AuditReport) -> str:
    lines = [f"Source: {report.source}", f"HTTP status: {report.status}", ""]
    if not report.findings:
        lines.append("PASS  No security-header findings.")
        return "\n".join(lines)
    lines.append("SEVERITY  RULE   HEADER                         MESSAGE")
    lines.append("--------- ------ ------------------------------ ----------------------------------------")
    for finding in report.findings:
        header = finding.header or "-"
        message = finding.message.replace("\n", " ")
        lines.append(f"{finding.severity.upper():<9} {finding.rule_id:<6} {header:<30} {message}")
    lines.extend(["", f"Findings: {len(report.findings)}"])
    return "\n".join(lines)


def render_json(report: AuditReport) -> str:
    return json.dumps(report.as_dict(), indent=2, ensure_ascii=False) + "\n"


def _sarif_level(severity: str) -> str:
    return {"error": "error", "warning": "warning", "info": "note"}.get(severity, "warning")


def render_sarif(report: AuditReport) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.message},
                "properties": {"header": finding.header} if finding.header else {},
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "headerlint", "version": "0.1.0", "rules": list(rules.values())}},
                "results": results,
                "properties": {"source": report.source, "httpStatus": report.status},
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render(report: AuditReport, output_format: str) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "sarif":
        return render_sarif(report)
    return render_table(report)

