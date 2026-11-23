"""The PR benchmark's agent tree (local_review --benchmark-view) equals scenario.materialize's."""

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scenario as sc  # noqa: E402

ROOT = sc.HERE.parent
sys.path.insert(0, str(ROOT / "security" / "handoff"))
from local_review import benchmark_view  # noqa: E402


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), "-c", "core.quotePath=false", *args],
                          check=True, capture_output=True, text=True, encoding="utf-8").stdout


def tree(path: Path) -> dict[str, str]:
    """Every file the agent's tools can list (git ls-files) with its content hash."""
    files = git(path, "ls-files", "--cached", "--others", "--exclude-standard").splitlines()
    return {f: hashlib.sha1((path / f).read_bytes()).hexdigest()
            for f in files if (path / f).is_file()}


@pytest.mark.parametrize("sid", ["S17", "D09"])  # app change; app change with new files
def test_benchmark_view_of_a_pr_on_this_branch_equals_materialize(tmp_path, sid):
    (scenario,) = sc.select(sid)
    pr, mat = tmp_path / "pr", tmp_path / "mat"
    git(ROOT, "worktree", "add", "--quiet", "--detach", str(pr), "HEAD")
    try:
        base = git(pr, "rev-parse", "HEAD").strip()
        subprocess.run(["git", "-C", str(pr), "apply", "--index", "--whitespace=nowarn", "-"],
                       input=scenario.patch_text().encode("utf-8"), check=True)
        git(pr, "-c", "user.email=t@example.com", "-c", "user.name=t", "-c",
            "commit.gpgsign=false", "commit", "--quiet", "--no-verify", "-m", "pr")
        head = git(pr, "rev-parse", "HEAD").strip()
        benchmark_view(pr, base, head)
        sc.materialize(scenario, mat, ROOT)
        assert tree(pr) == tree(mat)
    finally:
        for path in (pr, mat):
            subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(path)],
                           capture_output=True, check=False)
