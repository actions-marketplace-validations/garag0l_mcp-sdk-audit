"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, advisories, output
from .scanner import SEV_ORDER, scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="mcp-sdk-audit",
        description="Find MCP SDK versions with known advisories, and the code that stays exposed after you upgrade.",
    )
    p.add_argument("path", nargs="?", default=".", help="project directory or single file (default: .)")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="write report to this file instead of stdout")
    p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="medium",
        help="exit 1 if anything at or above this severity is found (default: medium)",
    )
    p.add_argument("--online", action="store_true", help="fetch the latest advisories from the GitHub Advisory Database")
    p.add_argument("--advisories", metavar="FILE", help="use an advisories JSON file instead of the bundled snapshot")
    p.add_argument("--no-deps", action="store_true", help="skip lockfile checks")
    p.add_argument("--no-source", action="store_true", help="skip source code rules")
    p.add_argument("--include-tests", action="store_true", help="also apply source rules to test files and fixtures")
    p.add_argument("--list-rules", action="store_true", help="print the source rules and exit")
    p.add_argument("--update-snapshot", metavar="FILE", help=argparse.SUPPRESS)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)

    if a.list_rules:
        print(output.rules_table())
        return 0

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if a.update_snapshot:
        records = advisories.fetch(token)
        with open(a.update_snapshot, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"source": advisories.API, "advisories": records}, fh, indent=2)
            fh.write("\n")
        print(f"wrote {len(records)} advisories to {a.update_snapshot}")
        return 0

    if a.online:
        try:
            records = advisories.fetch(token)
        except OSError as e:
            print(f"warning: could not fetch advisories ({e}); using bundled snapshot", file=sys.stderr)
            records = advisories.load(a.advisories)
    else:
        records = advisories.load(a.advisories)

    if not os.path.exists(a.path):
        print(f"error: {a.path} does not exist", file=sys.stderr)
        return 2

    report = scan(a.path, records, deps=not a.no_deps, source=not a.no_source, include_tests=a.include_tests)

    if a.format == "json":
        rendered = output.as_json(report)
    elif a.format == "sarif":
        rendered = output.sarif(report)
    else:
        color = not a.no_color and not a.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        rendered = output.text(report, color=color)

    if a.output:
        with open(a.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered + "\n")
    else:
        sys.stdout.write(rendered + "\n")

    threshold = 0 if a.fail_on == "none" else SEV_ORDER[a.fail_on]
    return 1 if threshold and report.max_severity() >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
