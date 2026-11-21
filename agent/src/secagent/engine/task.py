"""Context for the Claude Code engine: findings payload, task prompt, masked working tree."""

from __future__ import annotations

import json

from secagent.context.diff import PrDiff
from secagent.context.redact import mask_line, redact
from secagent.context.sarif import Cluster
from secagent.engine.output import EngineOutput
from secagent.phases.review import HUNT, _fill, load_prompt
from secagent.stages import Prepared
from secagent.tools.fs import wrap_untrusted
from secagent.tools.registry import format_findings

NO_REQUIREMENTS = "(cấu hình này không cung cấp tài liệu quy tắc nghiệp vụ)"


def findings_payload(clusters: list[Cluster], diff: PrDiff) -> list[dict]:
    """One JSON-ready dict per cluster, the full list the engine can read from findings.json."""
    return [{
        "cluster_id": c.id,
        "finding_ids": c.ids,
        "tools": c.tools,
        "severity": c.severity,
        "cwes": c.cwes,
        "file": c.file,
        "line": c.line,
        "end_line": c.end_line,
        "in_diff": c.in_diff,
        "messages": [redact(f.message) for f in c.findings],
    } for c in clusters]


def build_task(prepared: Prepared, hunt: bool = True) -> str:
    diff = prepared.diff
    changed = "\n".join(f"- {path} (+{len(fd.added)} dòng)"
                        for path, fd in sorted(diff.files.items())) or "(không có)"
    requirements = (wrap_untrusted("docs/security-requirements.md", prepared.requirements)
                    if prepared.requirements else NO_REQUIREMENTS)
    return _fill(load_prompt("engine_file.md"), {
        "changed_files": changed,
        "diff": wrap_untrusted("PR diff", diff.text(max_lines=600)),
        "findings_table": format_findings(prepared.clusters),
        "requirements": requirements,
        "hunt": HUNT if hunt else "",
        "schema": json.dumps(EngineOutput.model_json_schema()),
    })


def mask_worktree(prepared: Prepared) -> int:
    """Replace the lines Gitleaks reported, in the real files of the working tree, by a mask.

    The engine reads files directly with Read, which has no knowledge of `secret_lines`.
    Returns the number of masked lines.
    """
    root = prepared.repo.resolve()
    masked = 0
    for rel, lines in prepared.secret_lines.items():
        path = (root / rel).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            continue
        with open(path, encoding="utf-8", errors="replace", newline="") as handle:
            rows = handle.read().splitlines(keepends=True)
        changed = False
        for number in lines:
            if 1 <= number <= len(rows):
                body = rows[number - 1].rstrip("\r\n")
                rows[number - 1] = mask_line() + rows[number - 1][len(body):]
                masked += 1
                changed = True
        if changed:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write("".join(rows))
    return masked
