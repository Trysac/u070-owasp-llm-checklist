# Bounded static hints combined with human answers per OWASP LLM risk

Status: accepted (generated, pending human review)

## Context

Teams shipping LLM features rarely review them against the OWASP Top 10 for LLM Applications 2025. Some risks leave static traces in code, others need a human judgement, and semgrep or bandit rules are not mapped to the LLM Top 10. The scanner reads untrusted repositories, so it must be safe to run and its output must never leak secrets.

## Decision

Ship ten single-line regex rules (P01 to P10, with P05 reading one call's argument text) as code in rules.py, plus ten questions, one per risk. A stdlib-only scanner walks the tree without following symlinks and bounds file size, file count, finding count, line length and call-text work. A report combines findings and answers per risk: failed, evidence-found, open or answered. Findings are labelled hints, and excerpts and notes mask long token-like runs. A single base error class ChecklistError carries a stable code.

## Consequences

The tool is deterministic, dependency-free and safe on hostile input, and the report is versioned and repeatable. Detection is shallow: single-line matching gives false positives and false negatives, there is no data-flow analysis or dynamic testing, and only Python, TypeScript and JavaScript files are examined. Masking can shorten long identifiers in excerpts. The console script cannot be declared until the build manifest is edited, so the CLI runs as python -m owasp_llm_checklist.
