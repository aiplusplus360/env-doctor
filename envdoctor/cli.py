"""``env-doctor`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .core import (DEFAULT_ENV_FILES, RULES, SEVERITIES, Finding, Report, analyze, gate,
                   parse_env, scan_paths, summarise)

__version__ = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="env-doctor",
        description="Compare environment variables that are declared with the ones read.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan code and env files")
    scan.add_argument("paths", nargs="*", help="files or directories (default: .)")
    scan.add_argument("--env", action="append", default=[], metavar="FILE",
                      help="declaration file; repeatable (default: discover .env files)")
    scan.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                      help="skip keys matching this glob; repeatable")
    scan.add_argument("--fail-on", default="error", choices=list(SEVERITIES) + ["never"])
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--no-info", action="store_true")

    rules = sub.add_parser("rules", help="list every rule and its remediation")
    rules.add_argument("--json", action="store_true")
    return parser


def _discover(paths: Sequence[str]) -> List[str]:
    found: List[str] = []
    for root in paths or ["."]:
        candidate = Path(root)
        if candidate.is_file():
            continue
        for name in DEFAULT_ENV_FILES:
            path = candidate / name
            if path.is_file():
                found.append(str(path))
    return found


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SystemExit("cannot read %s: %s" % (path, exc))


def _format(finding: Finding) -> str:
    location = ""
    if finding.file:
        location = " (%s:%d)" % (finding.file, finding.line) if finding.line else \
                   " (%s)" % finding.file
    key = (" %s" % finding.key) if finding.key else ""
    return "%s %s%s%s\n    %s" % (finding.severity.upper(), finding.rule, key,
                                  location, finding.message)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        payload = [rule.as_dict() for rule in RULES]
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for rule in RULES:
                print("%-22s %-8s %s" % (rule.code, rule.severity, rule.summary))
                print("%-31s fix: %s" % ("", rule.remediation))
        return 0

    roots = args.paths or ["."]
    env_files = args.env or _discover(roots)
    if not env_files:
        print("warning: no env files found; pass --env FILE to enable comparisons",
              file=sys.stderr)

    entries = []
    for path in env_files:
        entries.extend(parse_env(_read(path), path))

    files, usages, dynamic = scan_paths(roots)
    findings = analyze(usages, entries, dynamic, args.ignore)
    if args.no_info:
        findings = [finding for finding in findings if finding.severity != "info"]
    report = Report(findings, len(files), len(usages), len(entries), len(dynamic))

    if args.json:
        payload = report.as_dict()
        payload["env_files"] = env_files
        payload["scanned_files"] = files
        print(json.dumps(payload, indent=2))
    else:
        for finding in findings:
            print(_format(finding))
        summary = summarise(findings)
        print("\n%d error(s), %d warning(s), %d info(s)" % (
            summary["errors"], summary["warnings"], summary["infos"]))
        print("%d file(s) scanned, %d read(s), %d declaration(s) in %d env file(s)" % (
            len(files), len(usages), len(entries), len(env_files)))
    return 1 if gate(findings, args.fail_on) else 0
