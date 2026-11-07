"""The Pull Request diff: changed files and the line numbers each one adds."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from secagent.context.redact import redact

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_GIT_HEADER = re.compile(r"^diff --git a/(.*) b/(.*)$")
TRUNCATED = "… (cắt bớt, dùng get_diff(path))"


@dataclass
class FileDiff:
    path: str
    added: set[int] = field(default_factory=set)
    patch: str = ""


@dataclass
class PrDiff:
    files: dict[str, FileDiff] = field(default_factory=dict)

    @property
    def changed(self) -> set[str]:
        return set(self.files)

    def text(self, max_lines: int = 1500) -> str:
        lines = [line for fd in self.files.values() for line in fd.patch.splitlines()]
        if len(lines) > max_lines:
            lines = [*lines[:max_lines], TRUNCATED]
        return redact("\n".join(lines))


def parse_unified_diff(text: str) -> PrDiff:
    files: dict[str, FileDiff] = {}
    current: FileDiff | None = None
    old_path = ""
    buffer: list[str] = []
    in_hunk = False
    new_line = 0

    def flush() -> None:
        if current is not None:
            current.patch = "\n".join(buffer) + "\n"
            files[current.path] = current

    for raw in text.splitlines():
        header = _GIT_HEADER.match(raw)
        if header:
            flush()
            old_path = header.group(1)
            current, buffer, in_hunk = FileDiff(header.group(2)), [raw], False
            continue
        if current is None:
            continue
        buffer.append(raw)
        if not in_hunk:
            target = raw[4:].rstrip("\t")
            if raw.startswith("--- ") and target.startswith("a/"):
                old_path = target[2:]
            elif raw.startswith("+++ "):
                current.path = old_path if target == "/dev/null" else target.removeprefix("b/")
        hunk = _HUNK.match(raw)
        if hunk:
            in_hunk, new_line = True, int(hunk.group(1))
        elif in_hunk and raw.startswith("+"):
            current.added.add(new_line)
            new_line += 1
        elif in_hunk and raw.startswith(" "):
            new_line += 1
    flush()
    return PrDiff(files)


def load_diff(repo: Path, base: str, head: str) -> PrDiff:
    """Diff from the merge base of base and head (three dots), like the quality gate."""
    if base.startswith("-") or head.startswith("-"):
        raise ValueError("base/head must be commits, not options")
    out = subprocess.run(
        ["git", "-C", str(repo), "-c", "core.quotePath=false", "diff", "--no-color",
         "--no-renames", "-U3", f"{base}...{head}"],
        check=True, capture_output=True,
    ).stdout
    return parse_unified_diff(out.decode("utf-8", errors="replace"))
