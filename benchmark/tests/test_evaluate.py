import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "agent" / "src"))
pytest.importorskip("pydantic")  # secagent's dependencies: run with `uv run --project agent`
import evaluate as ev

SQLI = ev.Truth("S01-1", "S01", "SQLi tìm kiếm", "pattern", frozenset({"CWE-89"}),
                "app/medicare/patient/service.py", 40, 44,
                routes=frozenset({"GET /patients/search"}))
IDOR = ev.Truth("S01-2", "S01", "IDOR xuất bệnh án", "logic", frozenset({"CWE-639"}),
                "app/medicare/record/router.py", 80, 80)
ROOT = ev.Truth("S10-1", "S10", "container chạy root", "pattern", frozenset({"CWE-250"}),
                "infra/k8s/deployment.yaml", 20, 30, rules=frozenset({"CKV_K8S_23"}))


def P(file, start, end=None, cwes=(), rules=(), strict_only=False):
    return ev.Prediction(file, start, start if end is None else end, set(cwes), set(rules),
                         strict_only)


@pytest.mark.parametrize("pred,expected", [
    (P("app/medicare/patient/service.py", 42, cwes=["CWE-89"]), True),
    (P("app/medicare/patient/service.py", 37, cwes=["CWE-564"]), True),  # same family, -3
    (P("app/medicare/patient/service.py", 36, cwes=["CWE-89"]), False),  # 4 lines away
    (P("app/medicare/patient/service.py", 42, cwes=["CWE-79"]), False),  # other family
    (P("app/medicare/patient/other.py", 42, cwes=["CWE-89"]), False),
    (P("dast:GET /patients/search", 0, cwes=["CWE-89"]), True),
    (P("dast:GET /patients/{patient_id}", 0, cwes=["CWE-89"]), False),
])
def test_matching(pred, expected):
    assert ev.matches(pred, SQLI) is expected


def test_rule_names_match_findings_without_cwe():
    assert ev.matches(P("infra/k8s/deployment.yaml", 25, rules=["CKV_K8S_23"]), ROOT)
    assert not ev.matches(P("infra/k8s/deployment.yaml", 25, rules=["CKV_K8S_8"]), ROOT)


def test_score_counts_each_bug_once_and_needs_review_only_when_strict():
    preds = [P("app/medicare/patient/service.py", 41, cwes=["CWE-89"]),
             P("app/medicare/patient/service.py", 43, cwes=["CWE-89"]),  # second tool, same bug
             P("app/medicare/record/router.py", 80, cwes=["CWE-639"], strict_only=True),
             P("app/medicare/seed.py", 9, cwes=["CWE-330"])]  # no such bug: FP
    strict = ev.score(preds, [SQLI, IDOR], strict=True)
    lenient = ev.score(preds, [SQLI, IDOR], strict=False)
    assert (strict.tp, strict.fp, strict.fn) == ({"S01-1", "S01-2"}, 1, set())
    assert (lenient.tp, lenient.fp, lenient.fn) == ({"S01-1"}, 1, {"S01-2"})


def test_agent_predictions_use_cluster_location_or_evidence():
    clusters = [{"id": "F1", "file": "app/medicare/patient/service.py", "line": 41,
                 "end_line": 42, "cwes": ["CWE-89"], "rules": ["py/sql-injection"],
                 "finding_ids": ["codeql:py/sql-injection:app/medicare/patient/service.py:41"]}]
    report = {"findings": [
        {"verdict": "TP", "finding_ids": clusters[0]["finding_ids"], "cwe": "CWE-89",
         "file": "app/medicare/patient/service.py", "line": 41},
        {"verdict": "FP", "finding_ids": ["x"], "file": "a.py", "line": 1},
        {"verdict": "NEEDS_REVIEW", "finding_ids": [], "cwe": "CWE-639", "source": "agent",
         "file": "app/medicare/record/router.py", "line": 1,
         "evidence": [{"file": "app/medicare/record/router.py", "start_line": 79,
                       "end_line": 81}]},
    ]}
    preds = ev.agent_predictions(report, clusters)
    assert len(preds) == 2
    assert (preds[0].file, preds[0].start, preds[0].end, preds[0].rules) == (
        "app/medicare/patient/service.py", 41, 42, {"py/sql-injection"})
    assert (preds[1].start, preds[1].end, preds[1].strict_only) == (79, 81, True)
    assert ev.score(preds, [SQLI, IDOR], strict=True).tp == {"S01-1", "S01-2"}


def test_summary_groups_and_gate_counts():
    t = {"S01": [SQLI.__dict__ | {"cwes": ["CWE-89"]}, IDOR.__dict__ | {"cwes": ["CWE-639"]}],
         "D01": []}
    rows = [
        {"config": "C1", "scenario": "S01", "kind": "vuln", "rep": 1, "tp": ["S01-1"],
         "fp": 2, "fn": ["S01-2"], "tp_lenient": ["S01-1"], "fp_lenient": 2, "blocked": True,
         "gate_ok": True},
        {"config": "C1", "scenario": "D01", "kind": "decoy", "rep": 1, "tp": [], "fp": 1,
         "fn": [], "tp_lenient": [], "fp_lenient": 1, "blocked": True, "gate_ok": False},
        {"config": "C2", "scenario": "S01", "kind": "vuln", "rep": 1,
         "tp": ["S01-1", "S01-2"], "fp": 0, "fn": [], "tp_lenient": ["S01-1", "S01-2"],
         "fp_lenient": 0, "blocked": True, "gate_ok": True, "cost_usd": 0.05,
         "duration_s": 20.0, "wall_s": 25.0, "llm_calls": 5, "tool_calls": 7,
         "tokens_in": 30000, "tokens_out": 2000, "provider": "claude-mcp",
         "model": "claude-sonnet-5-5", "patches": 2, "patches_validated": 1,
         "patches_failed": 1},
        {"config": "C2", "scenario": "D01", "kind": "decoy", "rep": 1, "tp": [], "fp": 0,
         "fn": [], "tp_lenient": [], "fp_lenient": 0, "blocked": False, "gate_ok": True,
         "cost_usd": 0.01, "duration_s": 10.0, "wall_s": 12.0, "llm_calls": 2,
         "tool_calls": 2, "tokens_in": 9000, "tokens_out": 500, "provider": "claude-mcp",
         "model": "claude-sonnet-5-5", "patches": 0, "patches_validated": 0,
         "patches_failed": 0},
    ]
    summary = ev.summarize({"rows": rows, "truths": t})
    c1 = next(r for r in summary["C1"]["per_rep"] if r["view"] == "strict")
    c2 = next(r for r in summary["C2"]["per_rep"] if r["view"] == "strict")
    assert (c1["tp"], c1["fp"], c1["fn"]) == (1, 3, 1) and c1["precision"] == 0.25
    assert (c2["tp"], c2["fp"], c2["fn"], c2["f1"]) == (2, 0, 0, 1.0)
    assert summary["C2"]["recall_by_group"]["measured:neither"] == (1.0, 1)
    assert summary["C1"]["recall_by_group"]["category:logic"] == (0.0, 1)
    assert (summary["C1"]["clean_passed"], summary["C2"]["clean_passed"]) == (0, 1)
    assert summary["C2"]["cost"]["cost_usd"] == pytest.approx(0.03)
    assert summary["C2"]["model"] == ["claude-mcp/claude-sonnet-5-5"]
    text = ev.render(summary, {"rows": rows, "truths": t})
    assert "| C2 | claude-mcp/claude-sonnet-5-5 | 1 |" in text and "S01-2 IDOR" in text


def test_baseline_dast_findings_are_neither_tp_nor_fp():
    known = ev.baseline_dast([
        {"file": "dast:GET /login", "cwes": ["CWE-693"]},
        {"file": "app/medicare/seed.py", "cwes": ["CWE-330"]},  # only runtime findings count
    ])
    assert known == {("GET /login", "CWE-693")}
    preds = [P("dast:GET /login", 0, cwes=["CWE-693"]),  # pre-existing: known
             P("dast:GET /login", 0, cwes=["CWE-89"]),  # new on that route: FP here
             P("dast:GET /patients/search", 0, cwes=["CWE-89"])]  # the planted bug: TP
    s = ev.score(preds, [SQLI], strict=True, known=known)
    assert (s.tp, s.fp, s.known) == ({"S01-1"}, 1, 1)
