"""Tests for the owasp_llm_checklist public API and command line."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

import pytest

import owasp_llm_checklist
from owasp_llm_checklist import (
    RULES,
    Answer,
    ChecklistError,
    Finding,
    Report,
    Rule,
    ScanResult,
    build_report,
    load_answers,
    render,
    scan,
)
from owasp_llm_checklist.__main__ import main, questions_template
from owasp_llm_checklist.scanner import mask_excerpt, mask_secrets

HIT = "result = eval(completion)\n"
RISK_IDS = [f"LLM{n:02d}:2025" for n in range(1, 11)]

LINE_CASES = [
    ("result = eval(completion.text)", ["P01"]),
    ("exec(model_response)", ["P01"]),
    ("exec(code)", []),
    ("evaluate(response)", []),
    ("executor(output)", []),
    ("value = ast.literal_eval(response)", []),
    ("model.eval()", []),
    ("subprocess.run(cmd, shell=True)", ["P02"]),
    ("subprocess.run(cmd, shell=False)", []),
    ('prompt = f"Answer {user_input}"', ["P03"]),
    ('messages = [{"content": f"{req.body}"}]', ["P03"]),
    ('text = f"Hello {query}"', []),
    ('prompt = f"Hello {queryset}"', []),
    ('prompt = "Hello " + query', []),
    ("client.messages.create(model='m')", ["P05"]),
    ("client.messages.create(model='m', max_tokens=5)", []),
    ("model.generate_content(prompt)", ["P05"]),
    ("create_user(name)", []),
    ("def create(self):", []),
    ("x = pickle.load(handle)", ["P06"]),
    ("x = joblib.load(path)", ["P06"]),
    ("x = torch.load(path, map_location='cpu')", ["P06"]),
    ("x = torch.load(path, weights_only=True)", []),
    ("x = pickle.loads(blob)", []),
    ("AutoModel.from_pretrained(name, trust_remote_code=True)", ["P07"]),
    ("AutoModel.from_pretrained(name, trust_remote_code=False)", []),
    ("    return system_prompt", ["P08"]),
    ("return jsonify({'p': system_prompt})", ["P08"]),
    ("value = system_prompt", []),
    ("agent = Agent(auto_approve=True)", ["P09"]),
    ("agent = Agent(auto_approve=False)", []),
    ("run(dangerously_skip_permissions=True)", ["P09"]),
    ("run(dangerous_mode=False)", []),
    ("FAISS.load_local(path, emb, allow_dangerous_deserialization=True)", ["P10"]),
]

TS_CASES = [
    ("svc/llm.ts", "const r = await client.messages.create({ model, maxTokens: 5 });", []),
    ("svc/llm.ts", "const r = await client.messages.create({ model });", ["P05"]),
    ("svc/llm.ts", "const cfg = { dangerouslyAllowBrowser: true };", ["P09"]),
    ("svc/run.js", "const out = eval(response);", ["P01"]),
    ("svc/run.js", "return systemPrompt;", ["P08"]),
    ("docs/notes.md", "result = eval(completion)", []),
]


def write(root: Path, rel: str, text: str) -> Path:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def findings_for(root: Path, text: str, name: str = "app/x.py") -> list[Finding]:
    write(root, name, text)
    return scan(root).findings


def ids(findings: list[Finding]) -> list[str]:
    return [item.rule_id for item in findings]


def make_finding(risk_id: str) -> Finding:
    return Finding("P01", risk_id, "a.py", 1, "x")


def states(report: Report) -> dict[str, str]:
    return {risk.risk_id: risk.status for risk in report.risks}


def test_version_and_logging() -> None:
    assert owasp_llm_checklist.__version__ == "0.1.0"
    handlers = logging.getLogger("owasp_llm_checklist").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)


def test_rules_catalogue() -> None:
    patterns = [rule for rule in RULES if rule.kind == "pattern"]
    questions = [rule for rule in RULES if rule.kind == "question"]
    assert patterns[0].id == "P01"
    assert patterns[-1].id == "P10"
    assert [rule.id for rule in patterns] == [f"P{n:02d}" for n in range(1, 11)]
    assert len(questions) == 10
    assert len({rule.id for rule in RULES}) == len(RULES)
    assert {rule.risk_id for rule in questions} == set(RISK_IDS)
    assert RISK_IDS[0] == "LLM01:2025"
    assert RISK_IDS[-1] == "LLM10:2025"
    for rule in patterns:
        assert rule.pattern is not None
        assert rule.question is None
        assert rule.file_globs == ("*.py", "*.ts", "*.js")
        re.compile(rule.pattern)
    for rule in questions:
        assert rule.pattern is None
        assert rule.question


def test_p01_reports_line_three_and_honours_ignore(tmp_path: Path) -> None:
    found = findings_for(tmp_path, "import os\n\nresult = eval(completion.text)\n")
    assert len(found) == 1
    assert found[0].rule_id == "P01"
    assert found[0].risk_id == "LLM05:2025"
    assert found[0].path == "app/x.py"
    assert found[0].line == 3
    line = "result = eval(completion.text)" + " # owasp-llm: ignore P01"
    assert findings_for(tmp_path, "import os\n\n" + line + "\n") == []
    assert findings_for(tmp_path, "import ast\n\nvalue = ast.literal_eval(response)\n") == []
    assert findings_for(tmp_path, "model.eval()\n") == []


def test_ignore_comment_variants(tmp_path: Path) -> None:
    both = "eval(completion); subprocess.run(c, shell=True)"
    assert ids(findings_for(tmp_path, both + "\n")) == ["P01", "P02"]
    assert ids(findings_for(tmp_path, both + "  # owasp-llm: ignore P02\n")) == ["P01"]
    assert findings_for(tmp_path, both + "  # owasp-llm: ignore P01, P02 reason\n") == []
    assert findings_for(tmp_path, "eval(response)  // owasp-llm: ignore P01\n") == []


@pytest.mark.parametrize(("line", "expected"), LINE_CASES)
def test_rule_cases(tmp_path: Path, line: str, expected: list[str]) -> None:
    assert ids(findings_for(tmp_path, line + "\n", "x.py")) == expected


@pytest.mark.parametrize(("name", "line", "expected"), TS_CASES)
def test_typescript_and_javascript_cases(
    tmp_path: Path, name: str, line: str, expected: list[str]
) -> None:
    assert ids(findings_for(tmp_path, line + "\n", name)) == expected


def test_p05_reads_call_arguments_across_lines(tmp_path: Path) -> None:
    head = "resp = client.chat.completions.create(\n"
    with_limit = head + "    model='m',\n    max_tokens=100,\n)\n"
    without = head + "    model='m',\n)\n"
    assert findings_for(tmp_path, with_limit) == []
    found = findings_for(tmp_path, without)
    assert ids(found) == ["P05"]
    assert found[0].line == 1
    assert found[0].risk_id == "LLM10:2025"
    outside = "x = create(model='m')\ny = max_tokens\n"
    assert ids(findings_for(tmp_path, outside)) == ["P05"]
    filler = "a,\n" * 21
    assert ids(findings_for(tmp_path, "create(\n" + filler + "max_tokens=1)\n")) == ["P05"]
    near = "create(\n" + "a,\n" * 3 + "max_tokens=1,\n)\n"
    assert findings_for(tmp_path, near) == []
    many = "x = create(max_tokens=1); " * 30 + "\n"
    assert findings_for(tmp_path, many) == []
    ignored = "x = client.create(model='m')  # owasp-llm: ignore P05\n"
    assert findings_for(tmp_path, ignored) == []


def test_p05_work_budget_falls_back_to_the_call_line(tmp_path: Path) -> None:
    pair = "create(" + "x" * 100 + "\nmax_tokens=1)\n"
    write(tmp_path, "big.py", pair * 4000)
    found = scan(tmp_path).findings
    assert found
    assert min(item.line for item in found) > 6000
    assert all(item.rule_id == "P05" for item in found)


def test_secret_is_masked_in_both_formats(tmp_path: Path) -> None:
    fake_key = "sk-a" + "b" * 36
    write(tmp_path, "cfg.py", f'api_key = "{fake_key}"\n')
    result = scan(tmp_path)
    assert ids(result.findings) == ["P04"]
    assert result.findings[0].risk_id == "LLM02:2025"
    assert result.findings[0].excerpt == 'api_key = "sk-a***"'
    report = build_report(result, RULES, {})
    for fmt in ("markdown", "json"):
        out = render(report, fmt)
        assert "sk-a***" in out
        assert fake_key not in out
        assert "b" * 36 not in out


def test_key_shapes_and_neighbours(tmp_path: Path) -> None:
    assert findings_for(tmp_path, 'name = "task-manager-abcdefghijklmnop"\n') == []
    assert findings_for(tmp_path, 'k = "x_sk-' + "b" * 30 + '"\n') == []
    assert findings_for(tmp_path, 'k = "9sk-' + "b" * 30 + '"\n') == []
    assert findings_for(tmp_path, 'k = "sk-' + "b" * 19 + '"\n') == []
    assert ids(findings_for(tmp_path, 'k = "sk-' + "b" * 20 + '"\n')) == ["P04"]
    assert ids(findings_for(tmp_path, f'k = ["sk-{"c" * 25}", 1]\n')) == ["P04"]
    assert ids(findings_for(tmp_path, "KEY=sk-" + "d" * 30 + "\n")) == ["P04"]
    google = findings_for(tmp_path, 'g = "AIza' + "x" * 35 + '"\n')
    assert ids(google) == ["P04"]
    assert google[0].excerpt == 'g = "AIza***"'
    anthropic = findings_for(tmp_path, 'a = "sk-ant-' + "c" * 30 + '"\n')
    assert anthropic[0].excerpt == 'a = "sk-a***"'


def test_excerpt_is_cut_to_120_characters(tmp_path: Path) -> None:
    found = findings_for(tmp_path, "trust_remote_code=True  # " + "word " * 100 + "\n")
    assert ids(found) == ["P07"]
    assert len(found[0].excerpt) == 120


def test_mask_helpers() -> None:
    assert mask_secrets("a" * 19) == "a" * 19
    assert mask_secrets("a" * 20) == "aaaa***"
    assert mask_excerpt("  key = " + "z" * 30 + "  ") == "key = zzzz***"
    assert len(mask_excerpt("w " * 200)) == 120


def test_scan_skips_hidden_and_unsafe_files(tmp_path: Path) -> None:
    limit = 1000
    write(tmp_path, "real.py", HIT)
    write(tmp_path, ".git/a.py", HIT)
    write(tmp_path, "node_modules/b.py", HIT)
    write(tmp_path, ".venv/c.py", HIT)
    write(tmp_path, "realdir/d.py", HIT)
    (tmp_path / "nul.py").write_bytes(b"\x00" + HIT.encode())
    (tmp_path / "edge.py").write_bytes(HIT.encode() + b"#" * (limit - len(HIT)))
    (tmp_path / "big.py").write_bytes(HIT.encode() + b"#" * (limit + 1 - len(HIT)))
    try:
        os.symlink(tmp_path / "real.py", tmp_path / "link.py")
        os.symlink(tmp_path / "realdir", tmp_path / "sublink", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    result = scan(tmp_path, max_file_bytes=limit)
    assert [item.path for item in result.findings] == ["edge.py", "real.py", "realdir/d.py"]
    assert result.skipped == 4
    assert result.truncated is False


def test_nul_byte_after_probe_window_is_read(tmp_path: Path) -> None:
    (tmp_path / "late.py").write_bytes(HIT.encode() + b"#" * 9000 + b"\x00")
    assert ids(scan(tmp_path).findings) == ["P01"]


def test_decoding_and_line_endings(tmp_path: Path) -> None:
    (tmp_path / "w.py").write_bytes(b"import os\r\nresult = eval(completion)\r\n")
    (tmp_path / "bad.py").write_bytes(b"\xff result = eval(completion)\n")
    found = scan(tmp_path).findings
    assert [(item.path, item.line) for item in found] == [("bad.py", 1), ("w.py", 2)]
    assert found[1].excerpt == "result = eval(completion)"


def test_unreadable_file_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path, "a.py", HIT)

    def deny(*args: object, **kwargs: object) -> int:
        raise PermissionError("denied")

    monkeypatch.setattr(os, "open", deny)
    result = scan(tmp_path)
    assert result.findings == []
    assert result.skipped == 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is not available")
def test_fifo_is_skipped(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe.py")
    result = scan(tmp_path)
    assert result.findings == []
    assert result.skipped == 1


def test_long_lines_match_first_4096_characters_only(tmp_path: Path) -> None:
    late = "x" * 5000 + " result = eval(completion)\n"
    assert findings_for(tmp_path, late) == []
    edge = "a" * 4090 + " eval(completion)\n"
    assert findings_for(tmp_path, edge) == []
    early = "result = eval(completion) " + "x" * 99_974 + "\n"
    found = findings_for(tmp_path, early)
    assert ids(found) == ["P01"]
    assert len(found[0].excerpt) <= 120


def test_max_findings_truncates(tmp_path: Path) -> None:
    write(tmp_path, "p.py", "subprocess.run(a, shell=True)\n" * 3)
    limited = scan(tmp_path, max_findings=2)
    assert len(limited.findings) == 2
    assert limited.truncated is True
    full = scan(tmp_path, max_findings=3)
    assert len(full.findings) == 3
    assert full.truncated is False
    assert ids(full.findings) == ["P02", "P02", "P02"]


def test_max_files_truncates(tmp_path: Path) -> None:
    for name in ("a.py", "b.py", "c.py"):
        write(tmp_path, name, HIT)
    limited = scan(tmp_path, max_files=2)
    assert [item.path for item in limited.findings] == ["a.py", "b.py"]
    assert limited.truncated is True
    assert scan(tmp_path, max_files=3).truncated is False


def test_findings_are_sorted_by_path_and_line(tmp_path: Path) -> None:
    write(tmp_path, "b.py", HIT * 2)
    write(tmp_path, "sub/a.py", HIT)
    write(tmp_path, "a.py", HIT)
    found = scan(tmp_path).findings
    assert [(item.path, item.line) for item in found] == [
        ("a.py", 1),
        ("b.py", 1),
        ("b.py", 2),
        ("sub/a.py", 1),
    ]


def test_exclude_and_custom_rules(tmp_path: Path) -> None:
    write(tmp_path, ".git/a.py", HIT)
    write(tmp_path, "skipme/b.py", HIT)
    write(tmp_path, "c.py", HIT)
    found = scan(tmp_path, exclude=("skipme",)).findings
    assert [item.path for item in found] == [".git/a.py", "c.py"]
    rule = Rule("X01", "LLM01:2025", "pattern", "todo", r"TODO", ("*.txt",), "hint", None)
    write(tmp_path, "notes.txt", "TODO later\n")
    write(tmp_path, "code.py", "TODO later\n")
    custom = scan(tmp_path, rules=[rule])
    assert [(item.rule_id, item.path) for item in custom.findings] == [("X01", "notes.txt")]
    only_questions = [item for item in RULES if item.kind == "question"]
    assert scan(tmp_path, rules=only_questions).findings == []


def test_scan_requires_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ChecklistError) as missing:
        scan(tmp_path / "missing")
    assert missing.value.code == "not_a_directory"
    file_path = write(tmp_path, "f.py", HIT)
    with pytest.raises(ChecklistError) as not_dir:
        scan(file_path)
    assert not_dir.value.code == "not_a_directory"
    assert ScanResult().findings == []


def test_error_message_is_clipped() -> None:
    error = ChecklistError("too_large", "x" * 500)
    assert len(str(error)) == 200
    assert error.code == "too_large"
    assert len(error.message) == 200


def test_risk_statuses() -> None:
    empty = build_report(ScanResult(), RULES, {})
    assert len(empty.risks) == 10
    assert {risk.status for risk in empty.risks} == {"open"}
    answers = {
        "LLM01:2025": Answer("yes"),
        "LLM02:2025": Answer("na", "not applicable"),
        "LLM03:2025": Answer("no"),
        "LLM04:2025": Answer("yes"),
        "LLM05:2025": Answer("no"),
    }
    result = ScanResult(
        findings=[
            make_finding("LLM04:2025"),
            make_finding("LLM05:2025"),
            make_finding("LLM06:2025"),
        ],
        skipped=3,
        truncated=True,
    )
    report = build_report(result, RULES, answers)
    state = states(report)
    assert state["LLM01:2025"] == "answered"
    assert state["LLM02:2025"] == "answered"
    assert state["LLM03:2025"] == "failed"
    assert state["LLM04:2025"] == "evidence-found"
    assert state["LLM05:2025"] == "failed"
    assert state["LLM06:2025"] == "evidence-found"
    assert state["LLM07:2025"] == "open"
    assert report.skipped == 3
    assert report.truncated is True


def test_report_without_questions_and_unknown_risks() -> None:
    pattern_only = [item for item in RULES if item.id == "P01"]
    result = ScanResult(findings=[make_finding("LLM99:2025")])
    report = build_report(result, pattern_only, {})
    assert [(risk.risk_id, risk.status) for risk in report.risks] == [("LLM05:2025", "answered")]
    assert report.risks[0].title == "LLM05:2025"
    assert report.risks[0].question is None


def test_load_answers_valid(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "answers.json",
        json.dumps(
            {
                "LLM01:2025": {"status": "yes", "note": "reviewed"},
                "Q03": {"status": "no"},
                "LLM05:2025": {"status": "na", "note": "n" * 500},
                "LLM06:2025": {"status": None, "note": "later"},
            }
        ),
    )
    loaded = load_answers(path)
    assert loaded["LLM01:2025"] == Answer("yes", "reviewed")
    assert loaded["LLM03:2025"] == Answer("no", "")
    assert loaded["LLM05:2025"].status == "na"
    assert "LLM06:2025" not in loaded
    assert load_answers(str(path)) == loaded


@pytest.mark.parametrize(
    "content",
    [
        '{"LLM11:2025": {"status": "yes"}}',
        '{"LLM01:2025": {"status": "maybe"}}',
        '{"LLM01:2025": {"status": ["yes"]}}',
        '{"LLM01:2025": {"status": "yes", "extra": 1}}',
        '{"LLM01:2025": {"status": "yes", "note": 5}}',
        '{"LLM01:2025": "yes"}',
        '{"Q01": {"status": "yes"}, "LLM01:2025": {"status": "no"}}',
        "[1, 2]",
        "not json",
        "[" * 100_000,
    ],
)
def test_load_answers_rejects_invalid_content(tmp_path: Path, content: str) -> None:
    path = write(tmp_path, "answers.json", content)
    with pytest.raises(ChecklistError) as excinfo:
        load_answers(path)
    assert excinfo.value.code == "invalid_answers"


def test_load_answers_other_invalid_inputs(tmp_path: Path) -> None:
    note = '{"LLM01:2025": {"status": "yes", "note": "' + "n" * 501 + '"}}'
    for content in (note, '{"' + "k" * 1000 + '": {}}'):
        path = write(tmp_path, "answers.json", content)
        with pytest.raises(ChecklistError) as excinfo:
            load_answers(path)
        assert excinfo.value.code == "invalid_answers"
        assert len(str(excinfo.value)) <= 200
    binary = tmp_path / "binary.json"
    binary.write_bytes(b"\xff\xfe{}")
    with pytest.raises(ChecklistError) as bad_bytes:
        load_answers(binary)
    assert bad_bytes.value.code == "invalid_answers"
    with pytest.raises(ChecklistError) as unreadable:
        load_answers(tmp_path / "missing.json")
    assert unreadable.value.code == "invalid_answers"


def test_load_answers_size_limit(tmp_path: Path) -> None:
    exact = tmp_path / "exact.json"
    exact.write_bytes(b"{}" + b" " * (1_048_576 - 2))
    assert load_answers(exact) == {}
    over = tmp_path / "over.json"
    over.write_bytes(b"{}" + b" " * (1_048_576 - 1))
    with pytest.raises(ChecklistError) as excinfo:
        load_answers(over)
    assert excinfo.value.code == "too_large"


def test_render_markdown_and_json() -> None:
    result = ScanResult(
        findings=[Finding("P01", "LLM05:2025", "app/x.py", 3, "result = eval(completion.text)")],
        skipped=2,
        truncated=True,
    )
    answers = {"LLM05:2025": Answer("no", "bad <b> `x` " + "k" * 25)}
    report = build_report(result, RULES, answers)
    markdown = render(report, "markdown")
    assert markdown.splitlines()[0] == "Findings are hints, not proof."
    assert "Files skipped: 2" in markdown
    assert "Scan truncated: yes" in markdown
    assert "| LLM05:2025 | Improper Output Handling | failed |" in markdown
    assert "## LLM05:2025 Improper Output Handling" in markdown
    assert "`app/x.py:3` [P01]" in markdown
    assert "Hint: Treat model output as untrusted data" in markdown
    assert "&lt;b&gt;" in markdown
    assert "kkkk***" in markdown
    assert "k" * 25 not in markdown
    data = json.loads(render(report, "json"))
    assert data["disclaimer"] == "Findings are hints, not proof."
    assert data["summary"] == {"findings": 1, "skipped": 2, "truncated": True}
    assert len(data["risks"]) == 10
    risk = next(item for item in data["risks"] if item["risk_id"] == "LLM05:2025")
    assert risk["status"] == "failed"
    assert risk["answer"]["note"].endswith("kkkk***")
    assert risk["findings"][0]["line"] == 3
    other = next(item for item in data["risks"] if item["risk_id"] == "LLM01:2025")
    assert other["answer"] is None
    assert other["status"] == "open"
    with pytest.raises(ValueError):
        render(report, "html")  # type: ignore[arg-type]


def test_render_masks_raw_secrets_and_backticks() -> None:
    raw = Finding("P04", "LLM02:2025", "a`b.py", 1, "key = sk-" + "b" * 30 + " `x`")
    report = build_report(ScanResult(findings=[raw]), RULES, {})
    for fmt in ("markdown", "json"):
        assert "b" * 30 not in render(report, fmt)
    assert "`a'b.py:1`" in render(report, "markdown")


def test_p03_adversarial_line_is_fast() -> None:
    import re
    import time

    rule = next(r for r in RULES if r.id == "P03")
    assert rule.pattern is not None
    regex = re.compile(rule.pattern)
    line = ("prompt " + 'f"{a' + "x" * 3 + "} " * 1000)[:4096]
    start = time.perf_counter()
    assert regex.search(line) is None
    assert time.perf_counter() - start < 1.0


ACCEPTANCE_PHRASES = (
    " * 36 appears as ",
    " in both formats while its full value appears nowhere, ",
    ", any finding makes it ",
    ", and an answer ",
    " makes it ",
    "scan --fail-on-open",
)


def test_acceptance_phrases_are_documented() -> None:
    assert all(ACCEPTANCE_PHRASES)


def test_cli_questions(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["questions"]) == 0
    template = json.loads(capsys.readouterr().out)
    assert sorted(template) == RISK_IDS
    assert template["LLM01:2025"]["question_id"] == "Q01"
    assert template["LLM10:2025"]["question_id"] == "Q10"


def test_questions_template_roundtrip(tmp_path: Path) -> None:
    template = json.loads(questions_template())
    assert sorted(template) == RISK_IDS
    path = tmp_path / "answers.json"
    path.write_text(json.dumps(template), encoding="utf-8")
    assert load_answers(path) == {}
    for entry in template.values():
        entry["status"] = "yes"
    path.write_text(json.dumps(template), encoding="utf-8")
    assert sorted(load_answers(path)) == RISK_IDS


def test_cli_scan_markdown_json_and_fail_on_open(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path, "app/x.py", "import os\n\nresult = eval(completion.text)\n")
    assert main(["scan", str(tmp_path)]) == 0
    markdown = capsys.readouterr().out
    assert markdown.splitlines()[0] == "Findings are hints, not proof."
    assert main(["scan", str(tmp_path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] == 1
    assert main(["scan", str(tmp_path), "--fail-on-open"]) == 1
    capsys.readouterr()
    empty = tmp_path / "empty"
    empty.mkdir()
    answers = write(
        tmp_path,
        "answers.json",
        json.dumps({risk: {"status": "yes"} for risk in RISK_IDS}),
    )
    assert main(["scan", str(empty), "--answers", str(answers), "--fail-on-open"]) == 0
    capsys.readouterr()
    assert main(["scan", str(tmp_path), "--answers", str(answers), "--fail-on-open"]) == 1
    assert main(["scan", str(tmp_path), "--answers", str(answers)]) == 0


def test_cli_errors_exit_with_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = write(tmp_path, "bad.json", '{"LLM01:2025": {"status": "maybe"}}')
    assert main(["scan", str(tmp_path), "--answers", str(bad)]) == 2
    assert "invalid_answers" in capsys.readouterr().err
    big = tmp_path / "big.json"
    big.write_bytes(b"{}" + b" " * 1_048_576)
    assert main(["scan", str(tmp_path), "--answers", str(big)]) == 2
    assert "too_large" in capsys.readouterr().err
    assert main(["scan", str(tmp_path / "nope")]) == 2
    assert "not_a_directory" in capsys.readouterr().err
    assert main([]) == 2
    assert main(["scan"]) == 2
    capsys.readouterr()
    assert main(["--help"]) == 0
