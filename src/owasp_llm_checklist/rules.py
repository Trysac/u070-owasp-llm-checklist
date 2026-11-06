"""Rule catalogue for the OWASP Top 10 for LLM Applications 2025.

Source: OWASP GenAI Security Project, "OWASP Top 10 for LLM Applications 2025",
https://genai.owasp.org, published 2024-11-18. The ten risks run from LLM01:2025
Prompt Injection to LLM10:2025 Unbounded Consumption.

Pattern rules ``P01`` to ``P10`` are static hints, never proof. Every pattern is a
linear regular expression without nested quantifiers and is matched against at most
the first 4096 characters of one line; ``P05`` additionally reads the argument text of
a call (see :mod:`owasp_llm_checklist.scanner`). Question rules ``Q01`` to ``Q10`` need
a human answer, one per risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = ["RULES", "Rule"]

_GLOBS = ("*.py", "*.ts", "*.js")
_W = r"\w{0,60}"
_TRUE = r"(?:True|true)"

_P01 = r"\b(?:eval|exec)\s*\([^)\n]{0,200}?(?i:completion|response|output|reply|content)"
_P02 = r"\bsubprocess\s*\.\s*\w+\s*\([^\n]{0,300}?\bshell\s*=\s*True\b"
_P03_HEAD = r"^(?=[^\n]{0,4096}?(?i:prompt|messages))[^\n]{0,4096}?"
_P03_FSTR = r"(?<!\w)(?i:rf|fr|f)[\x22\x27][^\n{]{0,300}"
_P03_VAR = r"\{[^}\n]{0,100}?\b(?:request|req|query|user_input)\b"
_P03 = _P03_HEAD + _P03_FSTR + _P03_VAR
_P04 = r"\b(?:sk-ant-|sk-|AIza)[A-Za-z0-9_-]{20,}"
_P05 = r"(?<!def )(?<!function )\b(?:create|generate_content|complete)\s*\("
_P06 = r"\b(?:pickle|joblib|torch)\.load\s*\((?![^\n]*\bweights_only\s*=\s*True\b)"
_P07 = r"\btrust_remote_code\s*=\s*True\b"
_P08 = r"\b(?:return|jsonify)\b[^\n]{0,1000}?(?i:system_?prompt)"
_P09_AUTO = rf"\bauto_approve\s*[=:]\s*{_TRUE}\b"
_P09_DANGER = rf"\b(?!{_W}(?i:deserialization)){_W}(?i:dangerous){_W}\s*[=:]\s*{_TRUE}\b"
_P09 = _P09_AUTO + "|" + _P09_DANGER
_P10 = rf"\ballow_dangerous_deserialization\s*[=:]\s*{_TRUE}\b"


@dataclass(frozen=True)
class Rule:
    """One checklist rule: a static pattern hint or a question for a human.

    Attributes:
        id: Stable rule identifier (``P01`` to ``P10``, ``Q01`` to ``Q10``).
        risk_id: OWASP risk identifier such as ``LLM01:2025``.
        kind: ``"pattern"`` for a static hint, ``"question"`` for a human question.
        title: Short title (the risk name for question rules).
        pattern: Regular expression of a pattern rule, ``None`` for questions.
        file_globs: File name globs a pattern rule applies to.
        hint: Guidance shown next to a finding.
        question: Question text of a question rule, ``None`` for patterns.
    """

    id: str
    risk_id: str
    kind: Literal["pattern", "question"]
    title: str
    pattern: str | None
    file_globs: tuple[str, ...]
    hint: str
    question: str | None


def _risk_id(number: int) -> str:
    return f"LLM{number:02d}:2025"


def _pattern(rule_id: str, risk: int, title: str, pattern: str, hint: str) -> Rule:
    return Rule(
        id=rule_id,
        risk_id=_risk_id(risk),
        kind="pattern",
        title=title,
        pattern=pattern,
        file_globs=_GLOBS,
        hint=hint,
        question=None,
    )


def _question(number: int, title: str, question: str) -> Rule:
    risk_id = _risk_id(number)
    return Rule(
        id=f"Q{number:02d}",
        risk_id=risk_id,
        kind="question",
        title=title,
        pattern=None,
        file_globs=(),
        hint=f"Answer yes, no or na for {risk_id} in the answers file.",
        question=question,
    )


_PATTERN_RULES = (
    _pattern(
        "P01",
        5,
        "Model output passed to eval or exec",
        _P01,
        "Treat model output as untrusted data and never execute it.",
    ),
    _pattern(
        "P02",
        5,
        "Subprocess call with shell=True",
        _P02,
        "Pass an argument list without a shell and validate every value.",
    ),
    _pattern(
        "P03",
        1,
        "Prompt built from raw request input",
        _P03,
        "Keep user input in its own message instead of splicing it into instructions.",
    ),
    _pattern(
        "P04",
        2,
        "Hard-coded model API key",
        _P04,
        "Remove the key, rotate it and load it from a secret manager.",
    ),
    _pattern(
        "P05",
        10,
        "Model call without a token limit",
        _P05,
        "Set an explicit max_tokens (or equivalent) on every model call.",
    ),
    _pattern(
        "P06",
        3,
        "Unsafe model or pickle deserialization",
        _P06,
        "Load only trusted artifacts and pass weights_only=True or use safetensors.",
    ),
    _pattern(
        "P07",
        3,
        "Remote model code enabled",
        _P07,
        "Do not run remote model code; pin a reviewed revision instead.",
    ),
    _pattern(
        "P08",
        7,
        "System prompt returned to the caller",
        _P08,
        "Never return the system prompt to clients or logs.",
    ),
    _pattern(
        "P09",
        6,
        "Automatic approval of agent actions",
        _P09,
        "Require human approval for tool actions and avoid flags that disable safety.",
    ),
    _pattern(
        "P10",
        8,
        "Dangerous deserialization of vector data",
        _P10,
        "Only deserialize vector store files that you created yourself.",
    ),
)

_QUESTION_RULES = (
    _question(
        1,
        "Prompt Injection",
        "Is untrusted input kept apart from instructions and tested for prompt injection?",
    ),
    _question(
        2,
        "Sensitive Information Disclosure",
        "Are secrets and personal data kept out of prompts, training data and model output?",
    ),
    _question(
        3,
        "Supply Chain",
        "Are models, datasets and plugins pinned, verified and from trusted sources?",
    ),
    _question(
        4,
        "Data and Model Poisoning",
        "Is training, fine-tuning and retrieval data validated and its provenance tracked?",
    ),
    _question(
        5,
        "Improper Output Handling",
        "Is model output validated and encoded before it reaches interpreters or browsers?",
    ),
    _question(
        6,
        "Excessive Agency",
        "Are tools limited to least privilege, with human approval for risky actions?",
    ),
    _question(
        7,
        "System Prompt Leakage",
        "Does the system prompt hold no secrets, with access control enforced outside it?",
    ),
    _question(
        8,
        "Vector and Embedding Weaknesses",
        "Are vector stores access controlled per tenant and checked for poisoned content?",
    ),
    _question(
        9,
        "Misinformation",
        "Are answers grounded in sources, with users told about possible errors?",
    ),
    _question(
        10,
        "Unbounded Consumption",
        "Are token, rate, cost and time limits enforced for every model call?",
    ),
)

RULES: tuple[Rule, ...] = _PATTERN_RULES + _QUESTION_RULES
"""All rules: pattern rules ``P01`` to ``P10`` followed by questions ``Q01`` to ``Q10``."""
