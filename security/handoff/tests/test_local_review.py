import os
import stat
import subprocess
from pathlib import Path

import pytest
from local_review import clean_path, hidden_conflicts, hide, pick_run


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), "-c", "core.quotePath=false", *args],
                          check=True, capture_output=True, text=True, encoding="utf-8").stdout


def listed(repo: Path) -> str:
    return git(repo, "ls-files", "--cached", "--others", "--exclude-standard")


@pytest.fixture
def repo(tmp_path: Path):
    """A repo whose base holds an answer key; head changes app.py only."""
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "benchmark" / "S01").mkdir(parents=True)
    (tmp_path / "benchmark" / "S01" / "ground_truth.yaml").write_text("answer\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "benchmark-results.md").write_text("S01-1 IDOR\n")
    (tmp_path / "docs" / "security-requirements.md").write_text("R-01\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    base = git(tmp_path, "rev-parse", "HEAD").strip()

    def commit(message: str) -> str:
        git(tmp_path, "add", "-A")
        git(tmp_path, "commit", "-q", "-m", message)
        return git(tmp_path, "rev-parse", "HEAD").strip()

    return tmp_path, base, commit


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


@pytest.mark.parametrize("raw,clean", [("benchmark", "benchmark"), ("benchmark/", "benchmark"),
                                       ("benchmark\\", "benchmark"), ("./docs/x.md", "docs/x.md")])
def test_clean_path(raw, clean):
    assert clean_path(raw) == clean


@pytest.mark.parametrize("raw", ["", ".", "/", "..", "../x", "docs/../.."])
def test_clean_path_refuses_the_root_and_escapes(raw):
    with pytest.raises(ValueError):
        clean_path(raw)


def test_hidden_conflicts_matches_paths_and_their_contents_only():
    changed = ["app/a.py", "benchmark/x.yaml", "benchmarks/y.py", "docs/b.md", "docs/bb.md"]
    assert hidden_conflicts(changed, ["benchmark", "docs/b.md"]) == ["benchmark/x.yaml",
                                                                     "docs/b.md"]


def test_hide_removes_directories_and_files_from_disk_and_index(repo):
    tree, base, commit = repo
    (tree / "app.py").write_text("x = 2\n")
    head = commit("head")
    hide(tree, base, head, ["benchmark", "docs/benchmark-results.md"])
    assert not (tree / "benchmark").exists() and not (tree / "docs/benchmark-results.md").exists()
    assert listed(tree).split() == ["app.py", "docs/security-requirements.md"]
    assert git(tree, "diff", "--name-only", base, head).split() == ["app.py"]


def test_hide_removes_read_only_files(repo):
    tree, base, commit = repo
    (tree / "app.py").write_text("x = 2\n")
    head = commit("head")
    key = tree / "benchmark" / "S01" / "ground_truth.yaml"
    os.chmod(key, stat.S_IREAD)
    hide(tree, base, head, ["benchmark"])
    assert not (tree / "benchmark").exists()
    assert not [f for f in listed(tree).splitlines() if f.startswith("benchmark/")]


@pytest.mark.parametrize("change", ["edit", "rename", "non_ascii"])
def test_hide_refuses_when_the_pr_changes_hidden_files(repo, change):
    tree, base, commit = repo
    if change == "edit":
        (tree / "benchmark" / "S01" / "ground_truth.yaml").write_text("changed\n")
    elif change == "rename":  # the agent's diff shows the deleted answer key
        (tree / "benchmark" / "S01" / "ground_truth.yaml").rename(tree / "moved.yaml")
    else:
        (tree / "benchmark" / "tên.txt").write_text("x\n")
    head = commit(change)
    with pytest.raises(SystemExit):
        hide(tree, base, head, ["benchmark"])
