from __future__ import annotations

from email.message import Message
from pathlib import Path

import pytest

from headerlint.cli import main
from headerlint.fetcher import FetchError, fetch_url, validate_public_url


class FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes = b""):
        self.status = status
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value
        self._body = body
        self.closed = False

    def getcode(self):
        return self.status

    def read(self, size: int = -1):
        if not self._body:
            return b""
        chunk, self._body = self._body[:size], self._body[size:]
        return chunk

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.urls = []

    def open(self, request, timeout):
        self.urls.append((request.full_url, timeout))
        return next(self.responses)


def test_private_and_local_targets_are_blocked():
    with pytest.raises(FetchError, match="localhost"):
        validate_public_url("http://localhost:8080/")
    with pytest.raises(FetchError, match="non-public"):
        validate_public_url("http://192.168.1.20/")


def test_public_url_and_redirect_are_mocked(monkeypatch):
    import headerlint.fetcher as fetcher

    monkeypatch.setattr(
        fetcher.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    opener = FakeOpener(
        [
            FakeResponse(302, {"Location": "/final"}),
            FakeResponse(200, {"Content-Length": "2"}, b"OK"),
        ]
    )
    monkeypatch.setattr(fetcher, "build_opener", lambda *handlers: opener)
    response = fetch_url("https://public.example/start", timeout=1)
    assert response.status == 200
    assert response.url == "https://public.example/final"
    assert len(opener.urls) == 2


def test_redirect_to_localhost_is_blocked(monkeypatch):
    import headerlint.fetcher as fetcher

    monkeypatch.setattr(
        fetcher.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 80))],
    )
    opener = FakeOpener([FakeResponse(302, {"Location": "http://127.0.0.1/admin"})])
    monkeypatch.setattr(fetcher, "build_opener", lambda *handlers: opener)
    with pytest.raises(FetchError, match="non-public"):
        fetch_url("http://public.example/start")
    assert len(opener.urls) == 1


def test_response_limit_is_enforced(monkeypatch):
    import headerlint.fetcher as fetcher

    monkeypatch.setattr(
        fetcher.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 80))],
    )
    opener = FakeOpener([FakeResponse(200, {"Content-Length": str(fetcher.MAX_RESPONSE_BYTES + 1)})])
    monkeypatch.setattr(fetcher, "build_opener", lambda *handlers: opener)
    with pytest.raises(FetchError, match="byte limit"):
        fetch_url("http://public.example/")


def test_cli_json_output_and_exit_code(tmp_path: Path, capsys):
    sample = tmp_path / "response.txt"
    sample.write_text("HTTP/1.1 200 OK\nContent-Type: text/html\n\n", encoding="ascii")
    code = main(["--sample", str(sample), "--format", "json"])
    assert code == 1
    output = capsys.readouterr().out
    assert '"findings"' in output


def test_cli_sarif_exit_zero(tmp_path: Path, capsys):
    sample = tmp_path / "response.txt"
    sample.write_text("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff\n\n", encoding="ascii")
    code = main(["--sample", str(sample), "--format", "sarif", "--exit-zero"])
    assert code == 0
    output = capsys.readouterr().out
    assert '"version": "2.1.0"' in output
