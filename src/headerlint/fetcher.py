"""Conservative HTTP fetching with SSRF and resource limits."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .models import HttpResponse


MAX_RESPONSE_BYTES = 256 * 1024
MAX_REDIRECTS = 3
MAX_TIMEOUT_SECONDS = 10.0


class FetchError(ValueError):
    """Raised when a URL is invalid, unsafe, or cannot be fetched safely."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class _RawResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


def validate_public_url(url: str) -> None:
    """Reject URLs that can reach local, private, or otherwise non-public hosts."""

    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise FetchError(f"invalid URL: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise FetchError("only http:// and https:// URLs are supported")
    if not host:
        raise FetchError("URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise FetchError("URLs with embedded credentials are not allowed")
    if parsed.fragment:
        raise FetchError("URL fragments are not sent to servers and are not accepted")
    if port is not None and not 1 <= port <= 65535:
        raise FetchError("URL port must be between 1 and 65535")
    normalized = host.rstrip(".").lower()
    if "%" in normalized:
        raise FetchError("IPv6 zone identifiers are not allowed in URLs")
    if normalized == "localhost" or normalized.endswith(".localhost"):
        raise FetchError("localhost targets are blocked")
    try:
        addresses = {ipaddress.ip_address(normalized)}
    except ValueError:
        try:
            infos = socket.getaddrinfo(normalized, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except OSError as exc:
            raise FetchError(f"could not resolve hostname: {host}") from exc
        try:
            addresses = {ipaddress.ip_address(info[4][0].split("%", 1)[0]) for info in infos}
        except (IndexError, KeyError, ValueError) as exc:
            raise FetchError("hostname resolution returned an invalid address") from exc
    if not addresses:
        raise FetchError(f"hostname has no addresses: {host}")
    for address in addresses:
        if (
            address.is_loopback
            or address.is_private
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            or not address.is_global
        ):
            raise FetchError(f"target resolves to a non-public address: {address}")


def _read_limited(response, max_bytes: int) -> bytes:  # type: ignore[no-untyped-def]
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            declared_length = 0
        if declared_length > max_bytes:
            raise FetchError(f"response exceeds the {max_bytes} byte limit")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(16 * 1024, max_bytes - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(f"response exceeds the {max_bytes} byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _open_once(opener, url: str, timeout: float) -> _RawResponse:  # type: ignore[no-untyped-def]
    request = Request(url, headers={"User-Agent": "headerlint/0.1", "Accept": "*/*"}, method="GET")
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    except (OSError, URLError, TimeoutError) as exc:
        raise FetchError(f"request failed: {exc}") from exc
    try:
        try:
            body = _read_limited(response, MAX_RESPONSE_BYTES)
            status = int(getattr(response, "status", None) or response.getcode() or 0)
            headers = {str(key): str(value) for key, value in response.headers.items()}
            return _RawResponse(status, headers, body)
        except FetchError:
            raise
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            raise FetchError(f"invalid HTTP response: {exc}") from exc
    finally:
        close = getattr(response, "close", None)
        if close:
            close()


def fetch_url(url: str, timeout: float = 5.0, max_redirects: int = MAX_REDIRECTS) -> HttpResponse:
    """Fetch a public URL while validating every redirect destination."""

    if not 0.1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise FetchError(f"timeout must be between 0.1 and {MAX_TIMEOUT_SECONDS:g} seconds")
    current = url
    # Do not inherit HTTP(S)_PROXY from the environment: proxy routing could
    # bypass the host validation above and send requests to an internal proxy.
    opener = build_opener(_NoRedirectHandler(), ProxyHandler({}))
    for redirect_count in range(max_redirects + 1):
        validate_public_url(current)
        raw = _open_once(opener, current, timeout)
        if 300 <= raw.status < 400:
            location = next((value for key, value in raw.headers.items() if key.lower() == "location"), None)
            if not location:
                return HttpResponse(raw.status, dict(raw.headers), current, raw.body)
            if redirect_count >= max_redirects:
                raise FetchError(f"too many redirects (limit {max_redirects})")
            current = urljoin(current, location)
            continue
        return HttpResponse(raw.status, dict(raw.headers), current, raw.body)
    raise FetchError("too many redirects")
