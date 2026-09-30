"""Parse local raw HTTP response samples."""

from __future__ import annotations

import json
from pathlib import Path
import re

from .models import HttpResponse


_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)", re.IGNORECASE)


class SampleError(ValueError):
    """Raised when a local response sample cannot be parsed."""


def parse_sample(path: str | Path, max_bytes: int = 256 * 1024) -> HttpResponse:
    """Read a raw response or small JSON fixture without making network requests."""

    sample_path = Path(path)
    if not sample_path.is_file():
        raise SampleError(f"sample does not exist or is not a file: {sample_path}")
    if sample_path.stat().st_size > max_bytes:
        raise SampleError(f"sample exceeds the {max_bytes} byte limit")
    raw = sample_path.read_bytes()
    if sample_path.suffix.lower() == ".json":
        return _parse_json(raw)
    return _parse_raw(raw)


def _parse_json(raw: bytes) -> HttpResponse:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SampleError(f"invalid JSON sample: {exc}") from exc
    if not isinstance(payload, dict):
        raise SampleError("JSON sample must be an object")
    try:
        status = int(payload.get("status", 200))
        headers_obj = payload["headers"]
    except (KeyError, TypeError, ValueError) as exc:
        raise SampleError("JSON sample requires an integer status and headers object") from exc
    if not isinstance(headers_obj, dict):
        raise SampleError("JSON sample headers must be an object")
    headers = {str(key): str(value) for key, value in headers_obj.items()}
    body = str(payload.get("body", "")).encode("utf-8")
    return HttpResponse(status, headers, str(payload.get("url", "local-sample")), body)


def _parse_raw(raw: bytes) -> HttpResponse:
    separator = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    head, _, body = raw.partition(separator)
    lines = head.decode("iso-8859-1").splitlines()
    if not lines:
        raise SampleError("response sample is empty")
    status = 200
    first_line = lines[0].strip()
    match = _STATUS_RE.match(first_line)
    header_lines = lines[1:] if match else lines
    if match:
        status = int(match.group(1))
    headers: dict[str, str] = {}
    for line in header_lines:
        if not line.strip():
            continue
        if ":" not in line:
            raise SampleError(f"invalid header line: {line!r}")
        name, value = line.split(":", 1)
        if not name.strip():
            raise SampleError("header name cannot be empty")
        normalized_name = name.strip()
        normalized_value = value.strip()
        existing_name = next(
            (key for key in headers if key.lower() == normalized_name.lower()), None
        )
        if existing_name is not None:
            # Repeated HTTP fields carry independent values. Keep them joined so
            # the audit rules can apply a conservative check to all values.
            headers[existing_name] = f"{headers[existing_name]}, {normalized_value}"
        else:
            headers[normalized_name] = normalized_value
    return HttpResponse(status, headers, "local-sample", body)
