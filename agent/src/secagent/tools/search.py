"""Regex search over the repository's files."""

from __future__ import annotations

import re
from fnmatch import fnmatch

from secagent.context.redact import redact
from secagent.tools.fs import RepoFS, ToolError, wrap_untrusted

MAX_PATTERN = 200


def search_code(fs: RepoFS, pattern: str, glob: str = "*.py", max_results: int = 50) -> str:
    if len(pattern) > MAX_PATTERN:
        return f"ERROR: pattern quá dài (tối đa {MAX_PATTERN} ký tự)"
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return f"ERROR: regex không hợp lệ: {exc}"
    hits: list[str] = []
    for rel in fs.files():
        if not fnmatch(rel, glob):
            continue
        try:
            lines = fs.lines(rel)
        except ToolError:
            continue
        for number, line in enumerate(lines, start=1):
            if regex.search(line):
                hits.append(f"{rel}:{number}: {line.strip()[:200]}")
                if len(hits) >= max_results:
                    break
        if len(hits) >= max_results:
            break
    if not hits:
        return "(không có kết quả)"
    note = f"\n… (dừng ở {max_results} kết quả)" if len(hits) >= max_results else ""
    return wrap_untrusted(f"search {pattern} in {glob}", redact("\n".join(hits))) + note
