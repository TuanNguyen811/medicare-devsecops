"""Unified-diff parsing for LLM-proposed patches.

Hunks are read using their header counts, so a body line such as "+++ x" or "--- y" is never
mistaken for a file header. The model's hunk line numbers are never trusted on their own:
`old_lines_match` checks them against the real file (git apply would silently accept an
offset, and a GitHub suggestion would overwrite the wrong lines).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class Hunk:
    old_start: int
    new_start: int
    lines: list[tuple[str, str]] = field(default_factory=list)  # (" " | "-" | "+", text)


@dataclass
class FilePatch:
    old_path: str | None  # None: the file is created
    new_path: str | None  # None: the file is deleted
    hunks: list[Hunk] = field(default_factory=list)


def _path(raw: str) -> str | None:
    path = raw.rstrip("\t").strip()
    if path == "/dev/null":
        return None
    return path[2:] if path.startswith(("a/", "b/")) else path


def parse_patch(text: str) -> list[FilePatch]:
    files: list[FilePatch] = []
    hunk: Hunk | None = None
    old_left = new_left = 0
    old_path: str | None = None
    for raw in text.splitlines():
        if hunk is not None and (old_left > 0 or new_left > 0):
            tag = raw[:1] if raw[:1] in ("+", "-", "\\") else " "
            if tag == "\\":
                continue  # "\ No newline at end of file"
            if tag == "-":
                old_left -= 1
            elif tag == "+":
                new_left -= 1
            else:
                old_left -= 1
                new_left -= 1
            hunk.lines.append((tag, raw[1:]))
            continue
        hunk = None
        if raw.startswith("--- "):
            old_path = _path(raw[4:])
        elif raw.startswith("+++ "):
            files.append(FilePatch(old_path, _path(raw[4:])))
        elif files and (match := _HUNK.match(raw)):
            hunk = Hunk(int(match[1]), int(match[3]))
            old_left = int(match[2]) if match[2] is not None else 1
            new_left = int(match[4]) if match[4] is not None else 1
            files[-1].hunks.append(hunk)
    return files


def patched_files(text: str) -> list[str]:
    return [f.new_path for f in parse_patch(text) if f.new_path]


def old_lines_match(file_patch: FilePatch, lines: list[str]) -> bool:
    """True when every hunk's context and removed lines sit at the stated line numbers."""
    for hunk in file_patch.hunks:
        expected = [text for tag, text in hunk.lines if tag != "+"]
        if not expected:
            continue
        start = hunk.old_start - 1
        actual = lines[start:start + len(expected)] if start >= 0 else []
        if len(actual) != len(expected) or any(
                a.rstrip() != e.rstrip() for a, e in zip(actual, expected, strict=True)):
            return False
    return True
