"""Test helpers (never imported by the package)."""

from __future__ import annotations

import copy
import itertools
import json
import shutil
import subprocess
from pathlib import Path

from secagent.llm.base import LLMResponse, ToolCall

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


# --- scripted LLM ---------------------------------------------------------------------------

_call_ids = itertools.count(1)


class ScriptedLLM:
    """LLMClient double: replays scripted responses (or raises scripted exceptions) in order
    and records what each request carried."""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.calls: list[dict] = []

    def complete(self, messages: list[dict], tools: list[dict],
                 tool_choice: str = "auto") -> LLMResponse:
        self.calls.append({"messages": copy.deepcopy(messages), "tool_choice": tool_choice,
                           "tool_names": [t["function"]["name"] for t in tools]})
        if not self.script:
            raise AssertionError("ScriptedLLM: no scripted response left")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def call(name: str, **args) -> ToolCall:
    return ToolCall(f"call_{next(_call_ids)}", name, json.dumps(args, ensure_ascii=False))


def raw_call(name: str, arguments: str) -> ToolCall:
    return ToolCall(f"call_{next(_call_ids)}", name, arguments)


def reply(*calls: ToolCall, content: str | None = None, reasoning: str | None = None,
          tin: int = 100, tout: int = 20) -> LLMResponse:
    return LLMResponse(content=content, tool_calls=list(calls), reasoning=reasoning,
                       tokens_in=tin, tokens_out=tout)
