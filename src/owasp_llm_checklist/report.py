"""Per-risk report built from scan findings and human answers."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from .answers import Answer
from .rules import Rule
from .scanner import Finding, ScanResult, mask_excerpt, mask_secrets

__all__ = ["DISCLAIMER", "Report", "RiskState", "RiskStatus", "build_report", "render"]

_log = logging.getLogger(__name__)

DISCLAIMER = "Findings are hints, not proof."
RiskState = Literal["failed", "evidence-found", "open", "answered"]


@dataclass(frozen=True)
class RiskStatus:
    """Status of one OWASP risk.

    Attributes:
        risk_id: Risk identifier such as ``LLM01:2025``.
        title: Risk name.
        status: ``failed``, ``evidence-found``, ``open`` or ``answered``.
        question: The question to answer, if any.
        answer: The human answer, if any.
        findings: Static findings mapped to this risk.
    """

    risk_id: str
    title: str
    status: RiskState
    question: str | None
    answer: Answer | None
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class Report:
    """The complete checklist report.

    Attributes:
        risks: One entry per risk, sorted by risk id.
        skipped: Number of files skipped by the scan.
        truncated: True when the scan stopped at a limit.
        hints: Rule id to hint text, used when rendering findings.
    """

    risks: tuple[RiskStatus, ...]
    skipped: int
    truncated: bool
    hints: Mapping[str, str] = field(default_factory=dict)


def _status(
    answer: Answer | None,
    findings: Sequence[Finding],
    question: str | None,
) -> RiskState:
    if answer is not None and answer.status == "no":
        return "failed"
    if findings:
        return "evidence-found"
    if question is not None and answer is None:
        return "open"
    return "answered"


def build_report(
    scan_result: ScanResult,
    rules: Sequence[Rule],
    answers: Mapping[str, Answer],
) -> Report:
    """Combine findings and answers into a per-risk report.

    A risk is ``failed`` if its answer is ``no``, else ``evidence-found`` if it has any
    finding, else ``open`` if its question is unanswered, else ``answered``.
    """
    titles: dict[str, str] = {}
    questions: dict[str, str] = {}
    hints: dict[str, str] = {}
    risk_ids: set[str] = set()
    for rule in rules:
        risk_ids.add(rule.risk_id)
        hints.setdefault(rule.id, rule.hint)
        if rule.kind == "question":
            titles.setdefault(rule.risk_id, rule.title)
            if rule.question is not None:
                questions.setdefault(rule.risk_id, rule.question)
    by_risk: dict[str, list[Finding]] = {}
    for finding in scan_result.findings:
        by_risk.setdefault(finding.risk_id, []).append(finding)
    risks: list[RiskStatus] = []
    for risk_id in sorted(risk_ids):
        answer = answers.get(risk_id)
        question = questions.get(risk_id)
        found = tuple(by_risk.get(risk_id, []))
        entry = RiskStatus(
            risk_id=risk_id,
            title=titles.get(risk_id, risk_id),
            status=_status(answer, found, question),
            question=question,
            answer=answer,
            findings=found,
        )
        risks.append(entry)
    _log.debug("report built: risks=%d findings=%d", len(risks), len(scan_result.findings))
    return Report(tuple(risks), scan_result.skipped, scan_result.truncated, hints)


def _inline(text: str) -> str:
    """Make ``text`` safe inside an inline code span on one line."""
    return " ".join(text.replace("`", "'").split())


def _plain(text: str) -> str:
    """Mask secrets, collapse whitespace and escape HTML in free text."""
    cleaned = " ".join(mask_secrets(text).split())
    return cleaned.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _risk_section(risk: RiskStatus, hints: Mapping[str, str]) -> list[str]:
    lines = ["", f"## {risk.risk_id} {risk.title}", "", f"- Status: {risk.status}"]
    if risk.question is not None:
        lines.append(f"- Question: {risk.question}")
    if risk.answer is not None:
        note = _plain(risk.answer.note)
        suffix = f" - {note}" if note else ""
        lines.append(f"- Answer: {risk.answer.status}{suffix}")
    if risk.findings:
        lines.append("- Findings:")
        for finding in risk.findings:
            location = _inline(f"{finding.path}:{finding.line}")
            excerpt = _inline(mask_excerpt(finding.excerpt))
            lines.append(f"  - `{location}` [{finding.rule_id}] `{excerpt}`")
            hint = hints.get(finding.rule_id)
            if hint:
                lines.append(f"    Hint: {hint}")
    return lines


def _render_markdown(report: Report) -> str:
    total = sum(len(risk.findings) for risk in report.risks)
    truncated = "yes" if report.truncated else "no"
    lines = [
        DISCLAIMER,
        "",
        "# OWASP Top 10 for LLM Applications 2025 checklist",
        "",
        f"Findings: {total}. Files skipped: {report.skipped}. Scan truncated: {truncated}.",
        "",
        "| Risk | Title | Status |",
        "|---|---|---|",
    ]
    lines.extend(f"| {risk.risk_id} | {risk.title} | {risk.status} |" for risk in report.risks)
    for risk in report.risks:
        lines.extend(_risk_section(risk, report.hints))
    return "\n".join(lines)


def _finding_dict(finding: Finding, hints: Mapping[str, str]) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "risk_id": finding.risk_id,
        "path": finding.path,
        "line": finding.line,
        "excerpt": mask_excerpt(finding.excerpt),
        "hint": hints.get(finding.rule_id, ""),
    }


def _risk_dict(risk: RiskStatus, hints: Mapping[str, str]) -> dict[str, object]:
    answer: dict[str, str] | None = None
    if risk.answer is not None:
        answer = {"status": risk.answer.status, "note": mask_secrets(risk.answer.note)}
    return {
        "risk_id": risk.risk_id,
        "title": risk.title,
        "status": risk.status,
        "question": risk.question,
        "answer": answer,
        "findings": [_finding_dict(item, hints) for item in risk.findings],
    }


def _render_json(report: Report) -> str:
    payload: dict[str, object] = {
        "disclaimer": DISCLAIMER,
        "summary": {
            "findings": sum(len(risk.findings) for risk in report.risks),
            "skipped": report.skipped,
            "truncated": report.truncated,
        },
        "risks": [_risk_dict(risk, report.hints) for risk in report.risks],
    }
    return json.dumps(payload, indent=2)


def render(report: Report, fmt: Literal["markdown", "json"]) -> str:
    """Render ``report`` as Markdown or JSON.

    Markdown output starts with the line ``Findings are hints, not proof.`` Excerpts and
    notes are secret-masked in both formats.

    Raises:
        ValueError: if ``fmt`` is neither ``markdown`` nor ``json``.
    """
    if fmt == "markdown":
        return _render_markdown(report)
    if fmt == "json":
        return _render_json(report)
    raise ValueError("fmt must be 'markdown' or 'json'")
