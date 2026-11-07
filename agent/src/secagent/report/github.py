"""review.json: a GitHub pull-request review with one-click `suggestion` comments.

Only TP fixes whose patch is a single hunk in a single file, replacing lines this PR added,
become suggestions (GitHub can only comment on lines of the PR diff). The hunk's line numbers
come from the model, so the removed and context lines are checked against the file at the PR
head before anything is suggested. The workflow job agent-comment posts the file; secagent
itself never talks to GitHub.
"""

from __future__ import annotations

from collections.abc import Callable

from secagent.context.diff import PrDiff
from secagent.context.redact import redact
from secagent.models import Report
from secagent.patchutil import FilePatch, old_lines_match, parse_patch
from secagent.report.markdown import fence

HeadReader = Callable[[str], "list[str] | None"]


def single_hunk(patch: str) -> tuple[FilePatch, int, int, list[str]] | None:
    """(file patch, first replaced line, last replaced line, replacement lines) or None."""
    files = parse_patch(patch)
    if len(files) != 1 or len(files[0].hunks) != 1 or not files[0].new_path:
        return None
    hunk = files[0].hunks[0]
    items: list[tuple[str, int | None, str]] = []
    old_line = hunk.old_start
    for tag, text in hunk.lines:
        if tag == "+":
            items.append((tag, None, text))
        else:
            items.append((tag, old_line, text))
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
    return files[0], items[removed[0]][1], items[removed[-1]][1], replacement


def build_review(report: Report, diff: PrDiff, head_sha: str,
                 read_head: HeadReader) -> dict | None:
    """`read_head(path)` returns the file's lines at head_sha (None when unavailable)."""
    comments = []
    for e in report.findings:
        if e.verdict != "TP" or e.fix is None or not e.fix.patch:
            continue
        hunk = single_hunk(e.fix.patch)
        if hunk is None:
            continue
        file_patch, first, last, replacement = hunk
        path = file_patch.new_path
        changed = diff.files.get(path)
        if changed is None or not set(range(first, last + 1)) <= changed.added:
            continue
        head_lines = read_head(path)
        if head_lines is None or not old_lines_match(file_patch, head_lines):
            continue  # wrong line numbers: a suggestion here would overwrite other code
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
