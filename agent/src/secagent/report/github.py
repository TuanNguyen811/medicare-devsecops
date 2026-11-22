"""review.json: a GitHub pull-request review that pins each TP to the line it is about.

One comment per TP whose location (`file`:`line`, for an agent finding the first evidence
span) is a line this PR added: GitHub can only comment on lines of the PR diff. Other TPs
appear in report.md only. A comment states the problem and how to fix it, in words: the
developer writes the fix.
The workflow job agent-comment posts the file; secagent itself never talks to GitHub.
"""

from __future__ import annotations

from secagent.context.diff import PrDiff
from secagent.context.redact import redact
from secagent.models import Report, ReportEntry


def _body(e: ReportEntry) -> str:
    facts = " · ".join(x for x in (e.cwe, e.violated_rule and f"vi phạm {e.violated_rule}")
                       if x)
    lines = [f"**secagent · {e.verdict} · {e.severity}** — {e.title}"]
    if facts:
        lines.append(facts)
    lines += ["", e.reasoning]
    if e.fix is not None:
        lines += ["", f"**Đề xuất sửa:** {e.fix.description}"]
    return "\n".join(lines)


def build_review(report: Report, diff: PrDiff, head_sha: str) -> dict | None:
    comments = []
    for e in report.findings:
        if e.verdict != "TP" or not e.file:
            continue
        changed = diff.files.get(e.file)
        if changed is None or e.line not in changed.added:
            continue
        comments.append({"path": e.file, "line": e.line, "side": "RIGHT",
                         "body": redact(_body(e))})
    if not comments:
        return None
    return {"commit_id": head_sha, "event": "COMMENT", "comments": comments,
            "body": f"<!-- secagent-review:{head_sha} -->\nAI Security Agent nêu "
                    f"{len(comments)} lỗi tại dòng code của PR này; xem cách sửa trong từng "
                    "comment."}
