"""review.json: a GitHub pull-request review with one-click `suggestion` comments.

Only TP fixes whose patch is a single hunk in a single file, replacing lines this PR added,
become suggestions (GitHub can only comment on lines of the PR diff). The workflow job
agent-comment posts the file; secagent itself never talks to GitHub.
"""

from __future__ import annotations

import re

from secagent.context.diff import PrDiff
from secagent.context.redact import redact
from secagent.models import Report
from secagent.report.markdown import fence

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@")


def single_hunk(patch: str) -> tuple[str, int, int, list[str]] | None:
    """(path, first replaced line, last replaced line, replacement lines) or None."""
    lines = patch.splitlines()
    targets = [line[4:].rstrip("\t") for line in lines if line.startswith("+++ ")]
    hunks = [i for i, line in enumerate(lines) if _HUNK.match(line)]
    if len(targets) != 1 or len(hunks) != 1 or targets[0] == "/dev/null":
        return None
    path = targets[0].removeprefix("b/")
    old_line = int(_HUNK.match(lines[hunks[0]]).group(1))
    items: list[tuple[str, int | None, str]] = []
    for raw in lines[hunks[0] + 1:]:
        if raw.startswith("\\"):
            continue
        tag, text = (raw[:1] or " "), raw[1:]
        if tag == "+":
            items.append(("+", None, text))
        elif tag == "-":
            items.append(("-", old_line, text))
            old_line += 1
        else:
            items.append((" ", old_line, text))
            old_line += 1
    removed = [i for i, item in enumerate(items) if item[0] == "-"]
    if not removed:
        return None
    start, end = removed[0], removed[-1]
    while start > 0 and items[start - 1][0] == "+":
        start -= 1
    while end + 1 < len(items) and items[end + 1][0] == "+":
        end += 1
    replacement = [text for tag, _, text in items[start:end + 1] if tag != "-"]
    first, last = items[removed[0]][1], items[removed[-1]][1]
    return path, first, last, replacement


def build_review(report: Report, diff: PrDiff, head_sha: str) -> dict | None:
    comments = []
    for e in report.findings:
        if e.verdict != "TP" or e.fix is None or not e.fix.patch:
            continue
        hunk = single_hunk(e.fix.patch)
        if hunk is None:
            continue
        path, first, last, replacement = hunk
        changed = diff.files.get(path)
        if changed is None or not set(range(first, last + 1)) <= changed.added:
            continue
        body = (f"**secagent · {e.verdict} · {e.severity}** — {e.title}\n\n"
                f"{e.fix.description}\n\n" + fence("\n".join(replacement), "suggestion"))
        comment = {"path": path, "line": last, "side": "RIGHT", "body": redact(body)}
        if first != last:
            comment["start_line"] = first
            comment["start_side"] = "RIGHT"
        comments.append(comment)
    if not comments:
        return None
    return {"commit_id": head_sha, "event": "COMMENT", "comments": comments,
            "body": f"<!-- secagent-review:{head_sha} -->\nAI Security Agent đề xuất sửa "
                    f"{len(comments)} lỗi; bấm “Commit suggestion” để áp dụng."}
