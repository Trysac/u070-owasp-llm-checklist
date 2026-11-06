# Security

## Threat model

`owasp_llm_checklist` reads a repository that you point it at and reports static hints for the OWASP Top 10 for LLM Applications 2025. The repository content is untrusted input.

Defended:

- **No execution.** The scanner never imports, executes or evaluates scanned code. Files are read as bytes and decoded as UTF-8 with `errors="replace"`.
- **No symlinks.** The walk uses `os.walk(followlinks=False)`; symlinked files and directories are skipped and counted, and files are opened with `O_NOFOLLOW` where the platform supports it. Only regular files are read.
- **Bounded work.** File size (`max_file_bytes`, default 1,000,000 bytes), file count (`max_files`, default 20,000), finding count (`max_findings`, default 10,000), line length (first 4096 characters of each line) and the argument text read for rule `P05` (at most 20 lines, with a bounded amount of work per file) are limited. Binary files (a NUL byte in the first 8 KiB) are skipped. A scan that stops at `max_files` or `max_findings` reports `truncated = True`.
- **Excluded directories.** `.git`, `node_modules`, `.venv`, `dist` and `build` are never entered by default.
- **Linear patterns.** Regular expressions are written without nested quantifiers, so crafted lines are not expected to cause catastrophic backtracking.
- **Masked secrets.** Excerpts and answer notes mask every run of 20 or more `[A-Za-z0-9_-]` characters to its first four characters plus `***`. Excerpts are cut to 120 characters. Error messages hold at most 200 characters.
- **Bounded answers file.** The answers file must be UTF-8 JSON of at most 1 MiB; notes are limited to 500 characters; unknown ids, fields and statuses are rejected with `ChecklistError` (`invalid_answers`, or `too_large` above 1 MiB). Deeply nested JSON is rejected.
- **No logging configuration.** The library logs through `logging.getLogger(__name__)` with a `NullHandler` and does not log file content or secrets.

Not defended:

- Secrets that are split across lines or built at runtime from several parts are not detected by the key pattern, and secrets outside the masked shapes are not masked.
- Files beyond the size, count and finding limits are not examined; the report says so only through `truncated` and `skipped`.
- Malicious code in the scanned repository is not analysed; the tool reads it but does not judge it.
- The answers file is trusted to be honest: the tool records the human answer as given.

## Limits of the findings

Findings are hints, not proof. The scanner matches single lines (plus the argument text of one call for `P05`), so it misses code split in other ways and flags harmless code that looks similar. A risk without findings is not shown to be safe; it still needs a human answer.

## Out of scope

Dynamic testing, data-flow analysis and languages other than Python, TypeScript and JavaScript.

## Reporting a vulnerability

See the `SECURITY.md` file in the repository root.
