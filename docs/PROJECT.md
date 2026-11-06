# Project record

## Objective

Give teams a repeatable, code-tied review against the OWASP Top 10 for LLM Applications 2025: ten static pattern hints from the repository combined with ten human answers, rendered as one report.

## Scope

- In scope: the public API documented in [README.md](../README.md) (`scan`, `load_answers`, `build_report`, `render`, `RULES`, `ChecklistError`), the `python -m owasp_llm_checklist` command line, Python, TypeScript and JavaScript source files.
- Out of scope: dynamic testing, data-flow analysis, other languages, and any runtime dependency or I/O beyond reading the scanned tree and the answers file, unless an ADR accepts it.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 497484 / 131409 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.9894 |

## Factory run u070 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2652 | 114278 | 0 | 4246 | 0.5745 |
| fix-1 | claude-sonnet-5-5 | no | 10 | 1410 | 8691 | 74110 | 0.0433 |
| audit | claude-sonnet-5-5 | no | 12 | 5370 | 42014 | 144021 | 0.1732 |
| fix-2 | claude-sonnet-5-5 | no | 8 | 4292 | 16179 | 69250 | 0.0903 |
| fix-3 | claude-sonnet-5-5 | no | 10 | 1065 | 5626 | 76595 | 0.0324 |
| docs | claude-haiku-5-5 | no | 126570 | 4994 | 0 | 0 | 0.0758 |

Total: $0.9894. Prices: Anthropic list prices.
