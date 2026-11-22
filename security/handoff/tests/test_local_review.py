import subprocess
from pathlib import Path

from local_review import hidden_conflicts, hide, pick_run


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True,
                          text=True).stdout


def test_hidden_conflicts_only_reports_changed_files_inside_hidden_dirs():
    changed = ["app/a.py", "benchmark/x.yaml", "benchmarks.md"]
    assert hidden_conflicts(changed, ["benchmark", "docs/"]) == ["benchmark/x.yaml"]


def test_hide_removes_the_directory_from_disk_and_index(tmp_path: Path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "benchmark").mkdir()
    (tmp_path / "benchmark" / "ground_truth.yaml").write_text("answer\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    base = git(tmp_path, "rev-parse", "HEAD").strip()
    (tmp_path / "app.py").write_text("x = 2\n")
    git(tmp_path, "commit", "-q", "-am", "head")
    head = git(tmp_path, "rev-parse", "HEAD").strip()
    hide(tmp_path, base, head, ["benchmark"])
    assert not (tmp_path / "benchmark").exists()
    assert "benchmark" not in git(tmp_path, "ls-files", "--cached", "--others",
                                  "--exclude-standard")
    assert git(tmp_path, "diff", "--name-only", base, head).split() == ["app.py"]


def run(rid: int, prs: list[int], path: str = ".github/workflows/pr-security.yml") -> dict:
    return {"id": rid, "path": path, "pull_requests": [{"number": n} for n in prs]}


def test_pick_run_takes_this_prs_latest_pr_security_run():
    runs = {"workflow_runs": [
        run(1, [19]), run(5, [19]), run(9, [20]),                 # same head in PR 20
        run(7, [19], path=".github/workflows/main-ci.yml"),       # another workflow
    ]}
    assert pick_run(runs, 19) == 5
    assert pick_run(runs, 21) is None
    assert pick_run({}, 19) is None
