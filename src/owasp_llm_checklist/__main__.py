"""Command line interface, run with ``python -m owasp_llm_checklist``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal

from .answers import load_answers
from .errors import ChecklistError
from .report import build_report, render
from .rules import RULES
from .scanner import scan

__all__ = ["main", "questions_template"]


def questions_template() -> str:
    """Return an answers template (JSON) listing all ten questions."""
    template = {
        rule.risk_id: {
            "question_id": rule.id,
            "title": rule.title,
            "question": rule.question,
            "status": None,
            "note": "",
        }
        for rule in RULES
        if rule.kind == "question"
    }
    return json.dumps(template, indent=2)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="owasp-llm-checklist",
        description="Static checklist for the OWASP Top 10 for LLM Applications 2025.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="scan a repository and print the report")
    scan_parser.add_argument("root", help="repository directory to scan")
    scan_parser.add_argument("--answers", help="JSON file with answers to the ten questions")
    scan_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    scan_parser.add_argument(
        "--fail-on-open",
        action="store_true",
        help="exit 1 unless every risk is answered",
    )
    commands.add_parser("questions", help="print an answers template as JSON")
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    try:
        answers = load_answers(args.answers) if args.answers is not None else {}
        result = scan(Path(args.root))
    except ChecklistError as exc:
        sys.stderr.write(f"error: {exc.code}: {exc.message}\n")
        return 2
    report = build_report(result, RULES, answers)
    fmt: Literal["markdown", "json"] = "json" if args.format == "json" else "markdown"
    sys.stdout.write(render(report, fmt) + "\n")
    if args.fail_on_open and any(risk.status != "answered" for risk in report.risks):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the command line interface and return the process exit code.

    ``scan <root> [--answers FILE] [--format markdown|json] [--fail-on-open]`` prints the
    report; ``questions`` prints an answers template. Exit codes: 0 success, 1 when
    ``--fail-on-open`` finds a risk that is not answered, 2 for errors and bad usage.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    if args.command == "questions":
        sys.stdout.write(questions_template() + "\n")
        return 0
    return _run_scan(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
