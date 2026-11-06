"""Bounded static scanner for the pattern rules.

The scanner never imports or executes scanned code, never follows symbolic links and
bounds file size, line length, file count and finding count. Files are decoded as UTF-8
with ``errors="replace"`` and every line is matched on its first 4096 characters. A
finding on a line can be silenced with a trailing comment such as
``# owasp-llm: ignore P01``.
"""

from __future__ import annotations

import fnmatch
import functools
import logging
import os
import re
import stat
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path

from .errors import ChecklistError
from .rules import RULES, Rule

__all__ = ["Finding", "ScanResult", "mask_excerpt", "mask_secrets", "scan"]

_log = logging.getLogger(__name__)

MAX_LINE_CHARS = 4096
EXCERPT_CHARS = 120
_NUL_PROBE_BYTES = 8192
_MAX_CALL_LINES = 20
_MAX_CALLS_PER_LINE = 16
_CALL_BUDGET = 400_000
_SECRET_RUN = re.compile(r"[A-Za-z0-9_-]{20,}")
_IGNORE = re.compile(r"owasp-llm:\s*ignore\s+([^\n]{0,200})")
_RULE_ID = re.compile(r"\b[A-Z]\d{2}\b")
_TOKEN_LIMIT = re.compile(r"max_tokens|max_output_tokens|maxTokens")
_PAREN = re.compile(r"[()]")
_CALL_RULE_IDS = frozenset({"P05"})
_DEFAULT_EXCLUDE = (".git", "node_modules", ".venv", "dist", "build")

_Compiled = tuple[Rule, re.Pattern[str]]


@dataclass(frozen=True)
class Finding:
    """One static hint found in a file.

    Attributes:
        rule_id: Identifier of the pattern rule, for example ``P01``.
        risk_id: OWASP risk identifier, for example ``LLM05:2025``.
        path: POSIX path relative to the scan root.
        line: One-based line number.
        excerpt: The line, stripped, secret-masked and cut to 120 characters.
    """

    rule_id: str
    risk_id: str
    path: str
    line: int
    excerpt: str


@dataclass(frozen=True)
class ScanResult:
    """Outcome of :func:`scan`.

    Attributes:
        findings: Findings sorted by path, line and rule id.
        skipped: Number of files or directories skipped (symlinks, binary, oversized,
            unreadable).
        truncated: True when ``max_files`` or ``max_findings`` stopped the scan.
    """

    findings: list[Finding] = field(default_factory=list)
    skipped: int = 0
    truncated: bool = False


@dataclass
class _Counters:
    skipped: int = 0
    seen: int = 0
    truncated: bool = False


def mask_secrets(text: str) -> str:
    """Mask every run of 20 or more ``[A-Za-z0-9_-]`` characters.

    Each run is replaced by its first four characters followed by ``***``.
    """
    return _SECRET_RUN.sub(_mask_run, text)


def _mask_run(match: re.Match[str]) -> str:
    return match.group()[:4] + "***"


def mask_excerpt(text: str) -> str:
    """Return ``text`` stripped, secret-masked and cut to 120 characters."""
    return mask_secrets(text.strip())[:EXCERPT_CHARS]


@functools.lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _matches(name: str, globs: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, glob) for glob in globs)


def _ignored_ids(segment: str) -> frozenset[str]:
    if "owasp-llm:" not in segment:
        return frozenset()
    ids: set[str] = set()
    for match in _IGNORE.finditer(segment):
        ids.update(_RULE_ID.findall(match.group(1)))
    return frozenset(ids)


def _call_text(lines: Sequence[str], index: int, start: int) -> tuple[str, int]:
    """Return the argument text of a call and the number of characters read.

    ``start`` is the offset just after the opening parenthesis in line ``index``. At most
    20 lines are read; if the call is not closed by then, the text read so far is used.
    """
    parts: list[str] = []
    depth = 1
    consumed = 0
    for offset in range(_MAX_CALL_LINES):
        pos = index + offset
        if pos >= len(lines):
            break
        text = lines[pos][:MAX_LINE_CHARS]
        begin = start if offset == 0 else 0
        consumed += len(text) - begin + 1
        for match in _PAREN.finditer(text, begin):
            depth += 1 if match.group() == "(" else -1
            if depth == 0:
                end = match.start()
                parts.append(text[begin:end])
                return "\n".join(parts), consumed
        parts.append(text[begin:])
    return "\n".join(parts), consumed


def _missing_limit(
    lines: Sequence[str],
    index: int,
    segment: str,
    regex: re.Pattern[str],
    multiline: bool,
) -> tuple[bool, int]:
    """Return whether a matched call lacks a token limit, and the work spent."""
    used = 0
    for match in islice(regex.finditer(segment), _MAX_CALLS_PER_LINE):
        if multiline:
            text, consumed = _call_text(lines, index, match.end())
            used += consumed
        else:
            start = match.end()
            text = segment[start:]
        if _TOKEN_LIMIT.search(text) is None:
            return True, used
    return False, used


def _scan_lines(
    lines: Sequence[str],
    rel: str,
    rules: Sequence[_Compiled],
) -> Iterator[Finding]:
    budget = _CALL_BUDGET
    for index, raw in enumerate(lines):
        segment = raw[:MAX_LINE_CHARS]
        if not segment.strip():
            continue
        ignored = _ignored_ids(segment)
        for rule, regex in rules:
            if rule.id in ignored:
                continue
            if rule.id in _CALL_RULE_IDS:
                hit, used = _missing_limit(lines, index, segment, regex, budget > 0)
                budget -= used
            else:
                hit = regex.search(segment) is not None
            if hit:
                yield Finding(rule.id, rule.risk_id, rel, index + 1, mask_excerpt(segment))


def _read_text(path: str, max_bytes: int) -> str | None:
    """Read a regular, non-symlink, non-binary file of at most ``max_bytes`` bytes."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        return None
    if len(data) > max_bytes or b"\x00" in data[:_NUL_PROBE_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")


def _candidates(
    root_str: str,
    skip_names: frozenset[str],
    compiled: Sequence[_Compiled],
    max_files: int,
    counters: _Counters,
) -> Iterator[tuple[str, str, list[_Compiled]]]:
    """Yield ``(full path, relative POSIX path, applicable rules)`` in sorted order."""
    for dirpath, dirnames, filenames in os.walk(root_str, followlinks=False):
        kept: list[str] = []
        for dirname in sorted(dirnames):
            if dirname in skip_names:
                continue
            if os.path.islink(os.path.join(dirpath, dirname)):
                counters.skipped += 1
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in sorted(filenames):
            if filename in skip_names:
                continue
            active = [pair for pair in compiled if _matches(filename, pair[0].file_globs)]
            if not active:
                continue
            if counters.seen >= max_files:
                counters.truncated = True
                return
            counters.seen += 1
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root_str).replace(os.sep, "/")
            yield full, rel, active


def scan(
    root: Path,
    rules: Sequence[Rule] = RULES,
    *,
    max_file_bytes: int = 1_000_000,
    max_files: int = 20_000,
    max_findings: int = 10_000,
    exclude: Sequence[str] = _DEFAULT_EXCLUDE,
) -> ScanResult:
    """Scan the files under ``root`` with the pattern rules of ``rules``.

    Files are walked in sorted order without following symlinks. Symlinks, files with a
    NUL byte in the first 8 KiB, files over ``max_file_bytes`` and unreadable files are
    skipped and counted. Rule ``P05`` reads the argument text of a call (at most 20
    lines); after a bounded amount of work per file it only checks the call line.

    Args:
        root: Directory to scan.
        rules: Rules to apply; question rules are ignored here.
        max_file_bytes: Largest file that is read.
        max_files: Largest number of candidate files examined.
        max_findings: Largest number of findings collected.
        exclude: Directory or file names that are never entered or read.

    Raises:
        ChecklistError: with code ``not_a_directory`` when ``root`` is not a directory.
    """
    base = Path(root)
    if not base.is_dir():
        raise ChecklistError("not_a_directory", "scan root is not a directory")
    root_str = os.fspath(base)
    compiled: list[_Compiled] = [
        (rule, _compile(rule.pattern))
        for rule in rules
        if rule.kind == "pattern" and rule.pattern is not None
    ]
    counters = _Counters()
    findings: list[Finding] = []
    skip_names = frozenset(exclude)
    for full, rel, active in _candidates(root_str, skip_names, compiled, max_files, counters):
        text = _read_text(full, max_file_bytes)
        if text is None:
            counters.skipped += 1
            continue
        for finding in _scan_lines(text.split("\n"), rel, active):
            if len(findings) >= max_findings:
                counters.truncated = True
                break
            findings.append(finding)
        if counters.truncated:
            break
    findings.sort(key=lambda item: (item.path, item.line, item.rule_id))
    _log.debug(
        "scan done: files=%d findings=%d skipped=%d truncated=%s",
        counters.seen,
        len(findings),
        counters.skipped,
        counters.truncated,
    )
    return ScanResult(findings=findings, skipped=counters.skipped, truncated=counters.truncated)
