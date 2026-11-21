import json
from pathlib import Path

from test_cli import fix_patch, gate, scenario, verdict

from secagent.cli import main_finalize
from secagent.models import Report
from secagent.report.markdown import MARKER

ENGINE_FIXTURES = Path(__file__).parent / "fixtures" / "engine"


def execution(tmp_path, payload: dict) -> Path:
    path = tmp_path / "execution.json"
    result = "Đã xong.\n```json\n" + json.dumps(payload, ensure_ascii=False) + "\n```\n"
    path.write_text(json.dumps({
        "type": "result", "result": result, "num_turns": 4, "duration_ms": 2500,
        "total_cost_usd": 0.05, "usage": {"input_tokens": 10, "output_tokens": 5},
        "modelUsage": {"claude-sonnet-5-5": {}}}), encoding="utf-8")
    return path


def finalize_argv(repo, base, head, sarif_dir, out, exec_file, *extra):
    return ["--repo", str(repo), "--base", base, "--head", head, "--sarif-dir", str(sarif_dir),
            "--requirements", "docs/security-requirements.md", "--out", str(out),
            "--execution-file", str(exec_file), *extra]


def finalize(tmp_path, payload, score=None):
    repo, base, head, sarif_dir, line = scenario(tmp_path, score=score)
    out = tmp_path / "out"
    code = main_finalize(finalize_argv(repo, base, head, sarif_dir, out,
                                       execution(tmp_path, payload(line))))
    return code, out, sarif_dir, line


def load_report(out) -> Report:
    return Report.model_validate_json((out / "report.json").read_text(encoding="utf-8"))


def test_finalize_end_to_end(tmp_path):
    code, out, _, line = finalize(tmp_path, lambda n: {"verdicts": [verdict(n)]})
    assert code == 0
    for name in ("report.json", "report.md", "agent.sarif", "review.json", "verdicts.json",
                 "trace.jsonl"):
        assert (out / name).is_file(), name
    report = load_report(out)
    (entry,) = report.findings
    assert entry.verdict == "TP" and entry.fix.patch == fix_patch(line)
    assert report.meta.strategy == "claude-code"
    assert report.meta.model == "claude-sonnet-5-5"
    assert (report.meta.llm_calls, report.meta.tokens_in, report.meta.duration_s) == (4, 10, 2.5)
    assert report.meta.step_limit == 0 and report.meta.uncovered_before_check == 0
    assert "Engine: claude-code" in (out / "report.md").read_text(encoding="utf-8")
    saved = json.loads((out / "verdicts.json").read_text(encoding="utf-8"))
    assert saved["verdicts"][0]["cluster_id"] == "F1"
    kinds = [json.loads(x)["kind"] for x in
             (out / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    assert kinds[0] == "start" and kinds[-1] == "done"


def test_finalize_model_falls_back_to_option(tmp_path):
    repo, base, head, sarif_dir, line = scenario(tmp_path)
    path = tmp_path / "bare.json"
    path.write_text(json.dumps({"type": "result", "result": "```json\n" + json.dumps(
        {"verdicts": [verdict(line)]}) + "\n```"}), encoding="utf-8")
    out = tmp_path / "out"
    assert main_finalize(finalize_argv(repo, base, head, sarif_dir, out, path,
                                       "--model", "m-from-env")) == 0
    assert load_report(out).meta.model == "m-from-env"


def test_finalize_logs_tool_events(tmp_path):
    repo, base, head, sarif_dir, _ = scenario(tmp_path)
    out = tmp_path / "out"
    assert main_finalize(finalize_argv(repo, base, head, sarif_dir, out,
                                       ENGINE_FIXTURES / "messages.json")) == 0
    events = [json.loads(x) for x in
              (out / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    tools = [e for e in events if e["kind"] == "engine_tool"]
    assert [e["name"] for e in tools] == ["Read", "Grep"]


def test_finalize_report_drives_gate(tmp_path):
    _, out, sarif_dir, _ = finalize(tmp_path, lambda n: {"verdicts": [verdict(n, "TP")]})
    assert gate(sarif_dir, out).returncode == 1
    _, out_fp, sarif_fp, _ = finalize(tmp_path / "fp", lambda n: {"verdicts": [verdict(n, "FP")]})
    assert gate(sarif_fp, out_fp).returncode == 0, gate(sarif_fp, out_fp).stdout
    _, out_crit, sarif_crit, _ = finalize(
        tmp_path / "crit", lambda n: {"verdicts": [verdict(n, "FP")]}, score="9.8")
    assert gate(sarif_crit, out_crit).returncode == 1
    assert gate(sarif_crit, out_crit, "--labels", "security-reviewed").returncode == 0


def test_finalize_missing_and_unknown_clusters(tmp_path):
    code, out, _, _ = finalize(
        tmp_path, lambda n: {"verdicts": [{**verdict(n), "cluster_id": "F9"}]})
    assert code == 0
    report = load_report(out)
    assert [e.verdict for e in report.findings] == ["NEEDS_REVIEW"]
    assert report.meta.uncovered_before_check == 1
    trace = (out / "trace.jsonl").read_text(encoding="utf-8")
    assert "unknown_cluster" in trace and "F9" in trace


def test_finalize_duplicate_verdicts_most_severe_wins(tmp_path):
    code, out, _, _ = finalize(
        tmp_path / "a", lambda n: {"verdicts": [verdict(n, "FP"), verdict(n, "TP")]})
    assert code == 0
    assert [e.verdict for e in load_report(out).findings] == ["TP"]
    _, out, _, _ = finalize(
        tmp_path / "b", lambda n: {"verdicts": [verdict(n, "TP"), verdict(n, "FP")]})
    assert [e.verdict for e in load_report(out).findings] == ["TP"]


def test_finalize_engine_failure_exits_2(tmp_path, capsys):
    repo, base, head, sarif_dir, _ = scenario(tmp_path)
    out = tmp_path / "out"
    assert main_finalize(finalize_argv(repo, base, head, sarif_dir, out,
                                       ENGINE_FIXTURES / "error.json")) == 2
    text = (out / "report.md").read_text(encoding="utf-8")
    assert text.startswith(MARKER) and "traditional" in text
    assert not (out / "report.json").exists()
    assert "engine_failed" in (out / "trace.jsonl").read_text(encoding="utf-8")
    assert "Traceback" not in capsys.readouterr().err


def test_finalize_missing_execution_file_exits_2(tmp_path, capsys):
    repo, base, head, sarif_dir, _ = scenario(tmp_path)
    out = tmp_path / "out"
    assert main_finalize(finalize_argv(repo, base, head, sarif_dir, out,
                                       tmp_path / "nope.json")) == 2
    assert (out / "report.md").read_text(encoding="utf-8").startswith(MARKER)
    assert not (out / "report.json").exists()
    assert "Traceback" not in capsys.readouterr().err


def test_finalize_unexpected_error_exits_2(tmp_path, capsys):
    repo, _base, head, sarif_dir, line = scenario(tmp_path)
    out = tmp_path / "out"
    code = main_finalize(finalize_argv(repo, "0" * 40, head, sarif_dir, out,
                                       execution(tmp_path, {"verdicts": [verdict(line)]})))
    assert code == 2
    assert (out / "report.md").read_text(encoding="utf-8").startswith(MARKER)
    assert "Traceback" not in capsys.readouterr().err


def test_finalize_out_not_creatable_exits_2(tmp_path, capsys):
    repo, base, head, sarif_dir, line = scenario(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    code = main_finalize(finalize_argv(repo, base, head, sarif_dir, blocker / "out",
                                       execution(tmp_path, {"verdicts": [verdict(line)]})))
    assert code == 2
    assert "Traceback" not in capsys.readouterr().err


def test_finalize_fp_without_anchor_downgraded(tmp_path):
    code, out, _, _ = finalize(tmp_path, lambda n: {"verdicts": [verdict(n, "FP", snippet=")")]})
    assert code == 0
    assert [e.verdict for e in load_report(out).findings] == ["NEEDS_REVIEW"]


def test_finalize_keeps_lf_line_endings(tmp_path):
    _, out, _, _ = finalize(tmp_path, lambda n: {"verdicts": [verdict(n)]})
    for name in ("report.json", "report.md", "agent.sarif", "review.json", "verdicts.json"):
        assert b"\r\n" not in (out / name).read_bytes(), name
