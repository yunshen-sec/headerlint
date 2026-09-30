# headerlint

`headerlint` audits HTTP response security headers. It is a small, read-only
review tool for defensive checks in development and CI. It does not exploit
applications, enumerate networks, bypass access controls, or perform a
penetration test.

## Authorized use

Only inspect response samples you own or have permission to review. Network
fetching is opt-in with `--url`, and the URL must resolve to a public host. The
client rejects localhost, private, loopback, link-local, multicast, reserved,
and unspecified addresses on every request and redirect. It also uses HTTPS
verification, a ten-second maximum timeout, a 256 KiB response cap, and at most
three redirects. These controls reduce accidental SSRF; they are not a
replacement for network egress controls.

The default input is a local sample, so running the tool without explicitly
choosing `--url` never makes a network request. Do not use `--url` against a
third party without written authorization.

## Install and run

```console
python -m pip install -e .
headerlint --sample examples/response.txt
headerlint --sample examples/response.txt --format json
headerlint --sample examples/response.txt --format sarif > results.sarif
```

Raw samples can contain an HTTP status line followed by headers and an optional
body. JSON samples use this shape:

```json
{
  "status": 200,
  "url": "https://example.invalid/",
  "headers": {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff"
  },
  "body": "optional"
}
```

To fetch an explicitly authorized public URL:

```console
headerlint --url https://example.com/ --format sarif
```

The command exits `0` when there are no warning/error findings, `1` when the
response has findings, and `2` for invalid input or a blocked/failed request.
Use `--exit-zero` when a report should not fail a pipeline.

## Checks

The current rules cover HSTS on HTTPS, CSP (including `unsafe-eval`), MIME
sniffing, clickjacking, Referrer-Policy, and Permissions-Policy. Missing headers
are warnings because applicability depends on the endpoint; clearly unsafe
values are errors. This is a focused review aid, not a complete application
security assessment.

## Development

```console
python -m pip install -e ".[test]"
python -m pytest
```

Tests use parser fixtures and mocked network responses. They never contact a
real target. Run the same test suite locally before opening a pull request.
If you add CI in a fork, keep it limited to these local fixtures and tests.

## License

MIT
