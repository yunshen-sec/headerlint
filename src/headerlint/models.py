"""Small data models shared by the parser, scanner, and output renderers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}


@dataclass(frozen=True)
class HttpResponse:
    """The portion of an HTTP response needed by the audit rules."""

    status: int
    headers: dict[str, str]
    url: str = "local-sample"
    body: bytes = b""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    remediation: str
    header: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "remediation": self.remediation,
            "header": self.header,
        }


@dataclass
class AuditReport:
    source: str
    status: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(SEVERITY_ORDER.get(item.severity, 1) >= 1 for item in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status,
            "passed": self.passed,
            "findings": [item.as_dict() for item in self.findings],
        }

