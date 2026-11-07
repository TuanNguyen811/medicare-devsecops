import pytest
from pydantic import ValidationError

from secagent.models import (
    Evidence,
    Fix,
    Meta,
    NewFindingArgs,
    Report,
    ReportEntry,
    VerdictArgs,
)

CONTRACT_META = {
    "model", "strategy", "started_at", "duration_s", "llm_calls", "tool_calls", "tokens_in",
    "tokens_out", "cost_usd", "step_limit", "limit_hit", "uncovered_before_check",
}
CONTRACT_ENTRY = {
    "finding_id", "finding_ids", "source", "verdict", "confidence", "severity", "cwe", "owasp",
    "violated_rule", "reasoning", "evidence", "exploit_scenario", "fix",
}


def _meta() -> Meta:
    return Meta(model="deepseek-chat", strategy="agent", started_at="2026-11-07T10:00:00+00:00",
                duration_s=1.5, llm_calls=3, tool_calls=4, tokens_in=1000, tokens_out=200,
                cost_usd=0.001, step_limit=13, limit_hit=False, uncovered_before_check=0)


def _verdict(**kw) -> dict:
    base = {"cluster_id": "F1", "verdict": "TP", "confidence": 0.9, "severity": "HIGH",
            "cwe": "CWE-89", "owasp": "A05", "violated_rule": None, "reasoning": "SQL ghép chuỗi",
            "evidence": [{"file": "app/a.py", "start_line": 3, "end_line": 3, "snippet": "x"}]}
    base.update(kw)
    return base


def test_report_matches_contract_2():
    entry = ReportEntry(
        finding_id="semgrep:r:app/a.py:3", finding_ids=["semgrep:r:app/a.py:3"], source="semgrep",
        title="r (semgrep)", verdict="TP", confidence=0.9, severity="HIGH", cwe="CWE-89",
        owasp="A05", violated_rule=None, reasoning="x",
        evidence=[Evidence(file="app/a.py", start_line=3, end_line=3)],
        exploit_scenario="y", fix=Fix(description="z", patch="--- a/x\n+++ b/x\n"),
        file="app/a.py", line=3)
    data = Report(meta=_meta(), findings=[entry]).model_dump(mode="json")
    assert set(data["meta"]) == CONTRACT_META | {"error"}
    assert CONTRACT_ENTRY <= set(data["findings"][0])
    assert data["findings"][0]["fix"]["validated"] is None


@pytest.mark.parametrize("bad", [
    {"confidence": 1.5},
    {"cwe": "89"},
    {"violated_rule": "R-1"},
    {"owasp": "A11"},
    {"verdict": "MAYBE"},
    {"reasoning": ""},
    {"evidence": [{"file": "a.py", "start_line": 5, "end_line": 4}]},
    {"evidence": [{"file": "a.py", "start_line": 0, "end_line": 1}]},
])
def test_verdict_args_validation(bad):
    with pytest.raises(ValidationError):
        VerdictArgs.model_validate(_verdict(**bad))


def test_verdict_args_accept_minimal_and_full():
    assert VerdictArgs.model_validate(_verdict()).verdict == "TP"
    minimal = VerdictArgs.model_validate({"cluster_id": "F2", "verdict": "NEEDS_REVIEW",
                                          "confidence": 0, "severity": "LOW", "reasoning": "?"})
    assert minimal.evidence == [] and minimal.fix is None and minimal.cwe is None


def test_new_finding_requires_evidence():
    data = {"title": "IDOR", "severity": "HIGH", "confidence": 0.8, "cwe": "CWE-639",
            "reasoning": "thiếu kiểm tra quyền", "evidence": []}
    with pytest.raises(ValidationError):
        NewFindingArgs.model_validate(data)
    data["evidence"] = [{"file": "app/r.py", "start_line": 1, "end_line": 2}]
    assert NewFindingArgs.model_validate(data).cwe == "CWE-639"
    with pytest.raises(ValidationError):
        NewFindingArgs.model_validate({**data, "cwe": None})
