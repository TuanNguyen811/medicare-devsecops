import sys
from pathlib import Path

from fakes import git, make_git_repo

from secagent.cli import main_validate
from secagent.models import Evidence, Fix, Meta, Report, ReportEntry
from secagent.phases.validate_patch import (
    ValidationResult,
    run_command,
    validate_patch,
    validate_report,
)

CHECK_SAFE = [sys.executable, "-c",
              "import sys; sys.exit(0 if 'safe' in open('m.py').read() else 1)"]
SCAN_OK = [sys.executable, "-c", "pass"]


def patch(old: str, new: str) -> str:
    return f"--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n-value = '{old}'\n+value = '{new}'\n"


def entry(p: str, severity="HIGH", n=1, verdict="TP") -> ReportEntry:
    return ReportEntry(finding_id=f"semgrep:r{n}:m.py:1", finding_ids=[f"semgrep:r{n}:m.py:1"],
                       source="semgrep", title=f"r{n}", verdict=verdict, confidence=0.9,
                       severity=severity, reasoning="x",
                       evidence=[Evidence(file="m.py", start_line=1, end_line=1)],
                       fix=Fix(description="sửa", patch=p), file="m.py", line=1)


def repo(tmp_path: Path) -> Path:
    return make_git_repo(tmp_path, {"m.py": "value = 'raw'\n"})


def test_valid_patch_applies_and_passes(tmp_path):
    result = validate_patch(repo(tmp_path), entry(patch("raw", "safe")), test_cmd=CHECK_SAFE,
                            scan_cmd=SCAN_OK)
    assert result == ValidationResult(True, True, True, result.note) and result.validated


def test_patch_that_does_not_apply(tmp_path):
    result = validate_patch(repo(tmp_path), entry(patch("nope", "safe")), test_cmd=CHECK_SAFE,
                            scan_cmd=SCAN_OK)
    assert not result.applied and not result.validated
    assert "không khớp" in result.note  # caught before git apply (it would accept an offset)


def test_patch_breaking_tests(tmp_path):
    result = validate_patch(repo(tmp_path), entry(patch("raw", "broken")), test_cmd=CHECK_SAFE,
                            scan_cmd=SCAN_OK)
    assert result.applied and result.tests_passed is False and not result.validated


def test_scan_failure_fails_validation(tmp_path):
    scan_fail = [sys.executable, "-c", "import sys; sys.exit(1)"]
    result = validate_patch(repo(tmp_path), entry(patch("raw", "safe")), test_cmd=CHECK_SAFE,
                            scan_cmd=scan_fail)
    assert result.tests_passed and result.scan_clean is False and not result.validated


def test_worktree_cleaned_up(tmp_path):
    r = repo(tmp_path)
    validate_patch(r, entry(patch("raw", "safe")), test_cmd=CHECK_SAFE, scan_cmd=None)
    validate_patch(r, entry(patch("nope", "safe")), test_cmd=CHECK_SAFE, scan_cmd=None)
    assert len(git(r, "worktree", "list").splitlines()) == 1
    assert (r / "m.py").read_text(encoding="utf-8") == "value = 'raw'\n"


def test_env_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "x-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "y-secret")
    code, output = run_command(
        [sys.executable, "-c",
         "import os; print(os.environ.get('LLM_API_KEY', 'absent'),"
         " os.environ.get('GITHUB_TOKEN', 'absent'))"], tmp_path, 30)
    assert code == 0 and output.strip() == "absent absent"


def test_run_command_timeout_and_missing_program(tmp_path):
    code, _ = run_command([sys.executable, "-c", "import time; time.sleep(5)"], tmp_path, 0.5)
    assert code == 124
    code, _ = run_command(["definitely-not-a-program-xyz"], tmp_path, 5)
    assert code == 127


def _write_report(out: Path, entries: list[ReportEntry]) -> None:
    meta = Meta(model="m", strategy="agent", started_at="t", duration_s=1, llm_calls=1,
                tool_calls=1, tokens_in=1, tokens_out=1, cost_usd=0, step_limit=13,
                limit_hit=False, uncovered_before_check=0)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(Report(meta=meta, findings=entries).model_dump_json(),
                                     encoding="utf-8")


def test_validate_report_caps_and_rewrites(tmp_path):
    r = repo(tmp_path)
    out = tmp_path / "out"
    _write_report(out, [entry(patch("raw", "safe"), "MEDIUM", 1),
                        entry(patch("raw", "broken"), "CRITICAL", 2),
                        entry(patch("raw", "safe"), "HIGH", 3),
                        entry(patch("raw", "safe"), "HIGH", 4, verdict="FP")])
    report = validate_report(r, out, max_patches=2, test_cmd=CHECK_SAFE, scan_cmd=SCAN_OK)
    fixes = {e.title: e.fix for e in report.findings}
    assert fixes["r2"].validated is False and fixes["r3"].validated is True
    assert fixes["r1"].validated is None and "vượt giới hạn" in fixes["r1"].validation_note
    assert fixes["r4"].validated is None and fixes["r4"].validation_note == ""
    saved = Report.model_validate_json((out / "report.json").read_text(encoding="utf-8"))
    assert {e.title: e.fix.validated for e in saved.findings}["r3"] is True
    assert "đã kiểm chứng" in (out / "report.md").read_text(encoding="utf-8")


def test_main_validate_without_report_is_noop(tmp_path, capsys):
    assert main_validate(["--out", str(tmp_path / "none"), "--repo", str(tmp_path)]) == 0
    assert "không có gì để kiểm chứng" in capsys.readouterr().err


def test_main_validate_runs_with_custom_commands(tmp_path):
    r = repo(tmp_path)
    out = tmp_path / "out"
    _write_report(out, [entry(patch("raw", "safe"))])
    code = main_validate(["--out", str(out), "--repo", str(r), "--test-cmd",
                          f'"{sys.executable}" -c "pass"', "--scan-cmd", "none"])
    assert code == 0
    saved = Report.model_validate_json((out / "report.json").read_text(encoding="utf-8"))
    assert saved.findings[0].fix.validated is True
