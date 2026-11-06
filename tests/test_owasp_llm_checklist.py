"""Behavior tests for the public API of owasp_llm_checklist."""

from __future__ import annotations

import pytest

import owasp_llm_checklist


def test_normalize_trims_and_lowercases() -> None:
    assert owasp_llm_checklist.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        owasp_llm_checklist.normalize(value)


def test_version_is_semver() -> None:
    parts = owasp_llm_checklist.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
