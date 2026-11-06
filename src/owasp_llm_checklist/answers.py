"""Loading and validating the answers file filled in by a human reviewer."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .errors import ChecklistError
from .rules import RULES

__all__ = ["MAX_ANSWERS_BYTES", "MAX_NOTE_CHARS", "Answer", "load_answers"]

_log = logging.getLogger(__name__)

MAX_ANSWERS_BYTES = 1_048_576
MAX_NOTE_CHARS = 500
_STATUS: dict[str, Literal["yes", "no", "na"]] = {"yes": "yes", "no": "no", "na": "na"}
_ENTRY_KEYS = frozenset({"status", "note", "question", "question_id", "title"})
_RISK_IDS = frozenset(rule.risk_id for rule in RULES if rule.kind == "question")
_QUESTION_TO_RISK = {rule.id: rule.risk_id for rule in RULES if rule.kind == "question"}


@dataclass(frozen=True)
class Answer:
    """A human answer to the question of one risk.

    Attributes:
        status: ``yes`` (mitigated), ``no`` (not mitigated) or ``na`` (not applicable).
        note: Free text of at most 500 characters.
    """

    status: Literal["yes", "no", "na"]
    note: str = ""


def _invalid(message: str) -> ChecklistError:
    return ChecklistError("invalid_answers", message)


def _read_bounded(path: Path | str) -> bytes:
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_ANSWERS_BYTES + 1)
    except OSError as exc:
        raise _invalid("answers file cannot be read") from exc
    if len(data) > MAX_ANSWERS_BYTES:
        raise ChecklistError("too_large", "answers file exceeds 1 MiB")
    return data


def _resolve_id(key: str) -> str:
    if key in _RISK_IDS:
        return key
    mapped = _QUESTION_TO_RISK.get(key)
    if mapped is None:
        raise _invalid(f"unknown id: {key[:50]!r}")
    return mapped


def _parse_entry(risk_id: str, value: object) -> Answer | None:
    if not isinstance(value, dict):
        raise _invalid(f"entry for {risk_id} must be an object")
    unknown = sorted(str(name)[:30] for name in value if name not in _ENTRY_KEYS)
    if unknown:
        raise _invalid(f"unknown field for {risk_id}: {unknown[0]!r}")
    note = value.get("note", "")
    if not isinstance(note, str) or len(note) > MAX_NOTE_CHARS:
        raise _invalid(f"note for {risk_id} must be text of at most 500 characters")
    status = value.get("status")
    if status is None:
        return None
    if not isinstance(status, str) or status not in _STATUS:
        raise _invalid(f"status for {risk_id} must be yes, no or na")
    return Answer(_STATUS[status], note)


def load_answers(path: Path | str) -> dict[str, Answer]:
    """Load the answers file and return the answers keyed by risk id.

    The file is a JSON object of at most 1 MiB whose keys are risk ids such as
    ``LLM01:2025`` (question ids ``Q01`` to ``Q10`` are accepted as aliases) and whose
    values are objects with ``status`` (``yes``, ``no``, ``na`` or null for unanswered)
    and an optional ``note`` of at most 500 characters.

    Raises:
        ChecklistError: ``too_large`` when the file exceeds 1 MiB, ``invalid_answers`` for
            unreadable files, malformed JSON, unknown ids, fields or statuses.
    """
    data = _read_bounded(path)
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise _invalid("answers file is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise _invalid("answers file must contain a JSON object")
    answers: dict[str, Answer] = {}
    seen: set[str] = set()
    for key, value in document.items():
        risk_id = _resolve_id(key)
        if risk_id in seen:
            raise _invalid(f"duplicate answer for {risk_id}")
        seen.add(risk_id)
        answer = _parse_entry(risk_id, value)
        if answer is not None:
            answers[risk_id] = answer
    _log.debug("answers loaded: %d", len(answers))
    return answers
