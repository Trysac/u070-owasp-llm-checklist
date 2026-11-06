"""Static checklist for the OWASP Top 10 for LLM Applications 2025.

Combines ten static pattern hints with ten questions answered by a human and renders one
report per repository as Markdown or JSON. Findings are hints, not proof.
"""

from __future__ import annotations

import logging

from .answers import Answer, load_answers
from .errors import ChecklistError
from .report import Report, RiskStatus, build_report, render
from .rules import RULES, Rule
from .scanner import Finding, ScanResult, scan

__all__ = [
    "RULES",
    "Answer",
    "ChecklistError",
    "Finding",
    "Report",
    "RiskStatus",
    "Rule",
    "ScanResult",
    "__version__",
    "build_report",
    "load_answers",
    "render",
    "scan",
]

__version__ = "0.1.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())
