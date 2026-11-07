"""Test helpers (never imported by the package)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MINIAPP = Path(__file__).parent / "fixtures" / "miniapp"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
        encoding="utf-8",
    ).stdout.strip()


def commit_all(repo: Path, message: str = "commit") -> str:
    git(repo, "add", "--all")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD")


def write_files(repo: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")


def make_git_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    """git init -b main, write the files, commit them; returns the repo path."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    write_files(repo, files)
    commit_all(repo, "base")
    return repo


def miniapp_repo(tmp_path: Path, extra: dict[str, str] | None = None) -> Path:
    """A committed git copy of tests/fixtures/miniapp (Contract 1 layout), plus extra files."""
    repo = tmp_path / "repo"
    shutil.copytree(MINIAPP, repo)
    git(repo, "init", "-q", "-b", "main")
    write_files(repo, extra or {})
    commit_all(repo, "base")
    return repo
