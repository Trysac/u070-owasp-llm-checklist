# Architecture

## Purpose

`trysac-owasp-llm-checklist` (import name `owasp_llm_checklist`) is a small, stdlib-only Python package. It scans a repository for static pattern hints of the OWASP Top 10 for LLM Applications 2025, combines them with human answers, and renders one report as Markdown or JSON.

## Shape

```text
caller code / CLI (__main__.py)
        |
        +-- scanner.scan()        reads files, matches RULES, bounded
        +-- answers.load_answers() reads and validates the answers JSON
        +-- report.build_report() combines findings and answers per risk
        +-- report.render()       Markdown or JSON output
```

- **Public API**: the names listed in `__all__` of `src/owasp_llm_checklist/__init__.py`.
- **Rules**: `src/owasp_llm_checklist/rules.py` defines `Rule` and the `RULES` tuple (`P01` to `P10`, `Q01` to `Q10`).
- **Errors**: `ChecklistError` with a stable `code`, raised by the answers loader and the scanner for a missing directory.
- **Side effects**: the scanner reads files under the given root; nothing is written. Logging uses `logging.getLogger(__name__)` with a `NullHandler`.

## Quality contract

The gates are described in [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
