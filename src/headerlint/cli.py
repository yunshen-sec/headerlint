"""Command-line interface for headerlint."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .fetcher import FetchError, fetch_url
from .models import AuditReport
from .output import render
from .parser import SampleError, parse_sample
from .rules import audit_response


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headerlint",
        description="Audit HTTP response security headers from a local sample or an explicitly supplied public URL.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample", metavar="PATH", help="local raw HTTP or JSON response sample")
    source.add_argument("--url", metavar="URL", help="explicit public http(s) URL to fetch")
    parser.add_argument("--format", choices=("table", "json", "sarif"), default="table")
    parser.add_argument("--timeout", type=float, default=5.0, help="network timeout in seconds (0.1-10)")
    parser.add_argument("--max-redirects", type=int, default=3, help="maximum safe redirects to follow (0-3)")
    parser.add_argument("--exit-zero", action="store_true", help="always exit successfully after producing a report")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.sample is not None:
            response = parse_sample(args.sample)
        else:
            if not 0 <= args.max_redirects <= 3:
                raise FetchError("max-redirects must be between 0 and 3")
            response = fetch_url(args.url, timeout=args.timeout, max_redirects=args.max_redirects)
        report = AuditReport(response.url, response.status, audit_response(response))
    except (SampleError, FetchError) as exc:
        print(f"headerlint: {exc}", file=sys.stderr)
        return 2
    print(render(report, args.format), end="")
    if args.exit_zero or report.passed:
        return 0
    return 1
