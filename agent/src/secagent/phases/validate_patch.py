"""Patch validation (spec 4.1 phase 2): apply a proposed fix in a throw-away worktree, run the
tests and the project's Semgrep rules. Fixed code decides; the LLM controls no command.

This runs the Pull Request's code, so it runs as its own CI step without secrets, and every
command gets a minimal environment (no LLM_API_KEY, no GITHUB_TOKEN).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from secagent.models import SEVERITY_RANK, Report, ReportEntry
from secagent.patchutil import old_lines_match, parse_patch, patched_files
from secagent.report.markdown import render_markdown

Runner = Callable[[list[str], Path, float], tuple[int, str]]
SAFE_ENV = ("PATH", "PATHEXT", "HOME", "USERPROFILE", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP",
            "LOCALAPPDATA", "APPDATA", "UV_CACHE_DIR", "XDG_CACHE_HOME", "DOCKER_HOST")
TAIL = 2000


@dataclass
class ValidationResult:
    applied: bool
    tests_passed: bool | None
    scan_clean: bool | None
    note: str

    @property
    def validated(self) -> bool:
        return self.applied and self.tests_passed is True and self.scan_clean is not False


def run_command(argv: list[str], cwd: Path, timeout: float) -> tuple[int, str]:
    env = {k: os.environ[k] for k in SAFE_ENV if k in os.environ}
    try:
        done = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, f"quá thời gian {timeout:.0f} s"
    except OSError as exc:
        return 127, f"không chạy được {argv[0]}: {type(exc).__name__}"
    return done.returncode, (done.stdout + done.stderr)[-TAIL:]


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=False)


def _positions_problem(worktree: Path, patch: str) -> str | None:
    """Why the patch's hunks do not sit where they claim (git apply would accept an offset)."""
    files = parse_patch(patch)
    if not files:
        return "bản vá không đúng định dạng unified diff"
    for file_patch in files:
        if file_patch.old_path is None:
            continue  # a new file has no existing lines to check
        target = (worktree / file_patch.old_path).resolve()
        try:
            if not target.is_relative_to(worktree.resolve()):
                return f"bản vá trỏ ra ngoài repo: {file_patch.old_path}"
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return f"không đọc được {file_patch.old_path}"
        if not old_lines_match(file_patch, lines):
            return f"bản vá không khớp nội dung {file_patch.old_path} tại số dòng đã nêu"
    return None


def validate_patch(repo: Path, entry: ReportEntry, *, test_cmd: list[str],
                   scan_cmd: list[str] | None, runner: Runner = run_command,
                   timeout_s: float = 240) -> ValidationResult:
    patch = entry.fix.patch if entry.fix else ""
    if not patch.strip():
        return ValidationResult(False, None, None, "không có bản vá")
    scratch = Path(tempfile.mkdtemp(prefix="secagent-patch-"))
    worktree = scratch / "wt"
    added = _git(repo, "worktree", "add", "--detach", str(worktree), "HEAD")
    try:
        if added.returncode != 0:
            return ValidationResult(False, None, None, "không tạo được worktree tạm")
        problem = _positions_problem(worktree, patch)
        if problem is not None:
            return ValidationResult(False, None, None, problem)
        patch_file = scratch / "fix.patch"
        patch_file.write_text(patch if patch.endswith("\n") else patch + "\n", encoding="utf-8")
        check = _git(worktree, "apply", "--check", str(patch_file))
        if check.returncode != 0:
            return ValidationResult(False, None, None,
                                    f"git apply thất bại: {check.stderr.strip()[-300:]}")
        _git(worktree, "apply", str(patch_file))
        code, output = runner(test_cmd, worktree, timeout_s)
        tests_passed = code == 0
        notes = ["test đạt" if tests_passed else f"test không đạt (mã {code}): {output[-300:]}"]
        scan_clean = None
        if scan_cmd:
            code, output = runner([*scan_cmd, *patched_files(patch)], worktree, timeout_s)
            scan_clean = code == 0
            notes.append("Semgrep sạch" if scan_clean else f"Semgrep còn báo: {output[-300:]}")
        return ValidationResult(True, tests_passed, scan_clean, "; ".join(notes))
    finally:
        _git(repo, "worktree", "remove", "--force", str(worktree))
        _git(repo, "worktree", "prune")
        shutil.rmtree(scratch, ignore_errors=True)


def validate_report(repo: Path, out: Path, *, max_patches: int = 2, test_cmd: list[str],
                    scan_cmd: list[str] | None, runner: Runner = run_command,
                    timeout_s: float = 240, head_sha: str | None = None) -> Report:
    report = Report.model_validate_json((out / "report.json").read_text(encoding="utf-8"))
    candidates = sorted((e for e in report.findings
                         if e.verdict == "TP" and e.fix is not None and e.fix.patch),
                        key=lambda e: -SEVERITY_RANK.get(e.severity, 0))
    for index, entry in enumerate(candidates):
        if index >= max_patches:
            entry.fix.validated = None
            entry.fix.validation_note = "không kiểm chứng (vượt giới hạn số bản vá)"
            continue
        result = validate_patch(repo, entry, test_cmd=test_cmd, scan_cmd=scan_cmd,
                                runner=runner, timeout_s=timeout_s)
        entry.fix.validated = result.validated
        entry.fix.validation_note = result.note
    (out / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(report, head_sha=head_sha), encoding="utf-8")
    return report
