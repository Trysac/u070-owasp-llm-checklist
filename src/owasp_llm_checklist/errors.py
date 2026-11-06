"""Typed error raised by the checklist library."""

from __future__ import annotations

from typing import Literal

__all__ = ["ChecklistError", "ErrorCode"]

ErrorCode = Literal["invalid_answers", "too_large", "not_a_directory"]

_MAX_MESSAGE_CHARS = 200


class ChecklistError(Exception):
    """Base error of the library.

    Attributes:
        code: Stable machine-readable error code.
        message: Human readable message, at most 200 characters.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        clipped = message[:_MAX_MESSAGE_CHARS]
        super().__init__(clipped)
        self.code: ErrorCode = code
        self.message: str = clipped
