import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "agent" / "src"))
pytest.importorskip("pydantic")  # secagent's dependencies: run with `uv run --project agent`
import evaluate as ev  # noqa: E402

SQLI = ev.Truth("S01-1", "S01", "SQLi tìm kiếm", "pattern", frozenset({"CWE-89"}),
                "app/medicare/patient/service.py", 40, 44,
                routes=frozenset({"GET /patients/search"}))
IDOR = ev.Truth("S01-2", "S01", "IDOR xuất bệnh án", "logic", frozenset({"CWE-639"}),
                "app/medicare/record/router.py", 80, 80)
ROOT = ev.Truth("S10-1", "S10", "container chạy root", "pattern", frozenset({"CWE-250"}),
                "infra/k8s/deployment.yaml", 20, 30, rules=frozenset({"CKV_K8S_23"}))


def P(file, start, end=None, cwes=(), rules=(), needs_review=False, extra=()):
    spans = [(file, start, start if end is None else end), *extra]
    return ev.Prediction(spans, set(cwes), set(rules), needs_review)


@pytest.mark.parametrize("pred,expected", [
    (P("app/medicare/patient/service.py", 42, cwes=["CWE-89"]), True),
    (P("app/medicare/patient/service.py", 37, cwes=["CWE-564"]), True),  # same family, -3
    (P("app/medicare/patient/service.py", 36, cwes=["CWE-89"]), False),  # 4 lines away
    (P("app/medicare/patient/service.py", 42, cwes=["CWE-79"]), False),  # other family
    (P("app/medicare/patient/other.py", 42, cwes=["CWE-89"]), False),
    (P("dast:GET /patients/search", 0, cwes=["CWE-89"]), True),
    (P("dast:GET /patients/{patient_id}", 0, cwes=["CWE-89"]), False),
    # any evidence location counts (first one points at a schema, the bug is in the service)
    (P("app/medicare/patient/schemas.py", 5, cwes=["CWE-89"],
       extra=[("app/medicare/patient/service.py", 43, 43)]), True),
])
def test_matching(pred, expected):
    assert ev.matches(pred, SQLI) is expected


def test_rule_names_match_findings_without_cwe():
    assert ev.matches(P("infra/k8s/deployment.yaml", 25, rules=["CKV_K8S_23"]), ROOT)
    assert not ev.matches(P("infra/k8s/deployment.yaml", 25, rules=["CKV_K8S_8"]), ROOT)


def test_score_counts_each_bug_once_and_needs_review_is_never_a_detection():
    preds = [P("app/medicare/patient/service.py", 41, cwes=["CWE-89"]),
             P("app/medicare/patient/service.py", 43, cwes=["CWE-89"]),  # second tool, same bug
             P("app/medicare/record/router.py", 80, cwes=["CWE-639"], needs_review=True),
             P("app/medicare/seed.py", 9, cwes=["CWE-330"])]  # no such bug: FP
    strict = ev.score(preds, [SQLI, IDOR], strict=True)
    lenient = ev.score(preds, [SQLI, IDOR], strict=False)
    # spec 5.3: strict counts NEEDS_REVIEW as an FP, lenient ignores it; neither credits a TP
    assert (strict.tp, strict.fp, strict.fn, strict.needs_review) == (
        {"S01-1"}, 2, {"S01-2"}, 1)
    assert (lenient.tp, lenient.fp, lenient.fn) == ({"S01-1"}, 1, {"S01-2"})


def test_agent_predictions_use_cluster_location_or_every_evidence_span():
    clusters = [{"id": "F1", "file": "app/medicare/patient/service.py", "line": 41,
                 "end_line": 42, "cwes": ["CWE-89"], "rules": ["py/sql-injection"],
                 "finding_ids": ["codeql:py/sql-injection:app/medicare/patient/service.py:41"]}]
    report = {"findings": [
        {"verdict": "TP", "finding_ids": clusters[0]["finding_ids"], "cwe": "CWE-89",
         "file": "app/medicare/patient/service.py", "line": 41},
        {"verdict": "FP", "finding_ids": ["x"], "file": "a.py", "line": 1},
        {"verdict": "TP", "finding_ids": [], "cwe": "CWE-639", "source": "agent",
         "file": "app/medicare/record/schemas.py", "line": 1,
         "evidence": [{"file": "app/medicare/record/schemas.py", "start_line": 3,
                       "end_line": 4},
                      {"file": "app/medicare/record/router.py", "start_line": 79,
                       "end_line": 81}]},
        {"verdict": "NEEDS_REVIEW", "finding_ids": [], "cwe": "CWE-89", "file": "b.py",
         "line": 2},
    ]}
    preds = ev.agent_predictions(report, clusters)
    assert len(preds) == 3
    assert preds[0].spans == [("app/medicare/patient/service.py", 41, 42)]
    assert preds[0].rules == {"py/sql-injection"}
    assert len(preds[1].spans) == 2 and preds[2].needs_review
    assert ev.score(preds, [SQLI, IDOR], strict=True).tp == {"S01-1", "S01-2"}


def test_baseline_dast_rules_are_known_on_every_route():
    known = ev.baseline_dast([
        {"file": "dast:GET /login", "cwes": ["CWE-693"], "rules": ["10038"]},
        {"file": "app/medicare/seed.py", "cwes": ["CWE-330"], "rules": ["B311"]},
    ])
    assert known == {"10038"}
    preds = [P("dast:GET /new-page", 0, cwes=["CWE-693"], rules=["10038"]),  # same rule: known
             P("dast:GET /login", 0, cwes=["CWE-89"], rules=["40018"]),  # new problem: FP
             P("dast:GET /patients/search", 0, cwes=["CWE-89"], rules=["40018"])]  # planted
    s = ev.score(preds, [SQLI], strict=True, known=known)
    assert (s.tp, s.fp, s.known) == ({"S01-1"}, 1, 1)


def _row(config, scenario, kind, rep, tp, fp, truths, **kw):
    return {"config": config, "scenario": scenario, "kind": kind, "rep": rep,
            "truths": truths, "tp": tp, "fp": fp, "fn": [], "fp_lenient": fp, "known": 0,
            "needs_review": 0, "blocked": kind == "vuln", "gate_ok": True, "failed": False,
            **kw}


def test_summary_counts_failed_runs_as_misses():
    t = {"S01": [SQLI.__dict__ | {"cwes": ["CWE-89"]}, IDOR.__dict__ | {"cwes": ["CWE-639"]}],
         "D01": []}
    cost = {"cost_usd": 0.05, "duration_s": 20.0, "wall_s": 25.0, "llm_calls": 5,
            "tool_calls": 7, "tokens_in": 30000, "tokens_out": 2000, "provider": "claude-mcp",
            "model": "claude-sonnet-5-5"}
    rows = [
        _row("C1", "S01", "vuln", 1, ["S01-1"], 2, 2),
        _row("C1", "D01", "decoy", 1, [], 1, 0, blocked=True, gate_ok=False),
        _row("C2", "S01", "vuln", 1, ["S01-1", "S01-2"], 0, 2, **cost),
        _row("C2", "D01", "decoy", 1, [], 0, 0, **cost),
        _row("C2", "S01", "vuln", 2, [], 0, 2, failed=True),  # failed rep: two misses
        _row("C2", "D01", "decoy", 2, [], 0, 0, **cost),
    ]
    summary = ev.summarize({"rows": rows, "truths": t})
    c1 = next(r for r in summary["C1"]["per_rep"] if r["view"] == "strict")
    c2 = [r for r in summary["C2"]["per_rep"] if r["view"] == "strict"]
    assert (c1["tp"], c1["fp"], c1["fn"], c1["precision"]) == (1, 3, 1, 0.25)
    assert [(r["tp"], r["fn"], r["recall"]) for r in c2] == [(2, 0, 1.0), (0, 2, 0.0)]
    assert c2[1]["precision"] is None  # nothing predicted: undefined, shown as "-"
    assert summary["C2"]["failed_runs"] == 1
    assert summary["C2"]["detection"]["S01-2"] == [1, 2]
    assert summary["C2"]["recall_by_group"]["measured:neither"] == (0.5, 2)
    assert summary["C1"]["recall_by_group"]["category:logic"] == (0.0, 1)
    assert summary["C2"]["cost"]["cost_usd"] == pytest.approx(0.05)
    text = ev.render(summary, {"rows": rows, "truths": t})
    assert "| C2 | claude-mcp/claude-sonnet-5-5 | 2 |" in text and "S01-2 IDOR" in text


def test_logic_bug_matches_on_violated_rule_when_cwe_family_differs():
    rate = ev.Truth("S07-1", "S07", "tỷ lệ BHYT từ client", "logic",
                    frozenset({"CWE-602"}), "app/medicare/billing/router.py", 100, 117,
                    violated_rules=frozenset({"R-04", "R-17"}))
    same_rule = P("app/medicare/billing/router.py", 96, 120, cwes=["CWE-639"])
    same_rule.violated_rule = "R-04"
    other_rule = P("app/medicare/billing/router.py", 96, 120, cwes=["CWE-639"])
    other_rule.violated_rule = "R-01"
    assert ev.matches(same_rule, rate)
    assert not ev.matches(other_rule, rate)
    assert not ev.matches(P("app/medicare/billing/router.py", 96, 120, cwes=["CWE-639"]), rate)
    moved = P("app/medicare/billing/service.py", 100, cwes=["CWE-639"])
    moved.violated_rule = "R-04"
    assert not ev.matches(moved, rate)  # the rule never replaces the location


def test_agent_predictions_carry_the_violated_rule():
    report = {"findings": [{"verdict": "TP", "cwe": "CWE-639", "violated_rule": "R-04",
                            "finding_ids": [], "file": "app/a.py", "line": 3,
                            "evidence": [{"file": "app/a.py", "start_line": 3,
                                          "end_line": 4}]}]}
    (pred,) = ev.agent_predictions(report, [])
    assert pred.violated_rule == "R-04"


def test_either_listed_rule_matches_and_no_rule_never_does():
    rate = ev.Truth("S07-1", "S07", "tỷ lệ BHYT từ client", "logic",
                    frozenset({"CWE-602"}), "app/medicare/billing/router.py", 100, 117,
                    violated_rules=frozenset({"R-04", "R-17"}))
    r17 = P("app/medicare/billing/router.py", 110, cwes=["CWE-639"])
    r17.violated_rule = "R-17"
    assert ev.matches(r17, rate)
    plain = ev.Truth("S01-1", "S01", "SQLi", "pattern", frozenset({"CWE-89"}),
                     "app/medicare/patient/service.py", 40, 44)
    no_rule = P("app/medicare/patient/service.py", 42, cwes=["CWE-639"])
    assert not ev.matches(no_rule, plain)  # None never matches an empty rule set


def test_ground_truth_rule_may_be_one_or_several():
    assert ev._rule_set(None) == frozenset()
    assert ev._rule_set("R-03") == {"R-03"}
    assert ev._rule_set(["R-04", "R-17"]) == {"R-04", "R-17"}


def test_added_lines_and_fp_on_existing_code_are_counted_apart():
    patch = ("diff --git a/infra/main.tf b/infra/main.tf\n--- a/infra/main.tf\n"
             "+++ b/infra/main.tf\n@@ -10,2 +10,4 @@\n a\n+b\n+c\n d\n"
             "--- /dev/null\n+++ b/infra/new.yaml\n@@ -0,0 +1,2 @@\n+x\n+y\n")
    added = ev.sc.added_lines(patch)
    assert added == {"infra/main.tf": {11, 12}, "infra/new.yaml": {1, 2}}
    old = P("infra/main.tf", 3, 5, rules=["CKV_AWS_144"])  # existing resource, untouched
    new = P("infra/main.tf", 11, 12, rules=["CKV_AWS_144"])  # on the added lines
    s = ev.score([old, new], [], strict=True, added=added)
    assert (s.fp, s.fp_old) == (2, 1)


def test_truths_are_written_as_json():
    import json

    rate = ev.Truth("S07-1", "S07", "x", "logic", frozenset({"CWE-602"}), "a.py", 1, 2,
                    violated_rules=frozenset({"R-17", "R-04"}))
    (data,) = json.loads(json.dumps(ev._truth_dicts({"S07": [rate]})))["S07"]
    assert data["violated_rules"] == ["R-04", "R-17"]


def test_a_bug_pinned_at_any_listed_location_matches_once():
    xss = ev.Truth("S06-1", "S06", "XSS", "pattern", frozenset({"CWE-79"}),
                   "app/templates/detail.html", 29, 29,
                   also=(("app/medicare/record/service.py", 108, 121),))
    sink = P("app/templates/detail.html", 30, cwes=["CWE-79"])
    source = P("app/medicare/record/service.py", 115, cwes=["CWE-80"])
    elsewhere = P("app/medicare/record/router.py", 115, cwes=["CWE-79"])
    assert ev.matches(sink, xss) and ev.matches(source, xss)
    assert not ev.matches(elsewhere, xss)
    s = ev.score([sink, source], [xss], strict=True)
    assert (s.tp, s.fp) == ({"S06-1"}, 0)  # two reports of the same bug: one TP, no FP
