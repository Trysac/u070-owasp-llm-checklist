# owasp-llm-checklist

[![PyPI version](https://img.shields.io/pypi/v/trysac-owasp-llm-checklist)](https://pypi.org/project/trysac-owasp-llm-checklist/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-owasp-llm-checklist)](LICENSE)
[![CI](https://github.com/Trysac/u070-owasp-llm-checklist/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u070-owasp-llm-checklist/actions/workflows/ci.yml)

Static checklist for the OWASP Top 10 for LLM Applications 2025 over a repository: ten static pattern hints plus ten questions answered by a human, rendered as Markdown or JSON.

## Problem

Teams shipping LLM features rarely review them against the OWASP Top 10 for LLM Applications, and a static PDF checklist is never tied to the code. Some risks can be hinted at statically (model output passed to eval, prompts built from raw request input, missing token limits); others need a human answer. This package combines both into one repeatable report. Findings are hints, not proof.

## Install

```sh
pip install trysac-owasp-llm-checklist
# or
uv add trysac-owasp-llm-checklist
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
from pathlib import Path

from owasp_llm_checklist import RULES, build_report, load_answers, render, scan

result = scan(Path("."))
answers = load_answers(Path("answers.json"))
report = build_report(result, RULES, answers)
print(render(report, "markdown"))
```

Command line (run as a module; no console script is declared):

```sh
python -m owasp_llm_checklist questions > answers.json
python -m owasp_llm_checklist scan <root> [--answers FILE] [--format markdown|json] [--fail-on-open]
```

## Public API

- `scan(root, rules=RULES, *, max_file_bytes=1_000_000, max_files=20_000, max_findings=10_000, exclude=...)` returns a `ScanResult` with `findings`, `skipped` and `truncated`. Symlinks are never followed.
- `load_answers(path)` returns `dict[str, Answer]`; `Answer.status` is `yes`, `no` or `na`, and `note` holds at most 500 characters. Keys may be risk ids such as `LLM01:2025` or question ids `Q01` to `Q10`. A null status means unanswered.
- `build_report(scan_result, rules, answers)` returns a `Report`. Each risk is `failed` (answer `no`), `evidence-found` (any finding), `open` (unanswered question) or `answered`.
- `render(report, fmt)` returns Markdown or JSON; `fmt` must be `markdown` or `json`, otherwise `ValueError`.
- `RULES` holds ten pattern rules (`P01` to `P10`) and ten question rules (`Q01` to `Q10`), one per risk.
- `ChecklistError` carries `code`: `invalid_answers`, `too_large` (answers file over 1 MiB) or `not_a_directory`.
- CLI exit codes: 0 success, 1 when `--fail-on-open` finds an unanswered risk, 2 for errors and bad usage.

Limits: pattern matching uses the first 4096 characters of each line; files over `max_file_bytes` (default 1,000,000), binary files and unreadable files are skipped and counted; excerpts are cut to 120 characters and secrets are masked.

## Why not semgrep or bandit

Semgrep and bandit are general static analysers and are not mapped to the OWASP Top 10 for LLM Applications. This package covers only the risks listed above and records a human answer for each risk.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and limits.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
