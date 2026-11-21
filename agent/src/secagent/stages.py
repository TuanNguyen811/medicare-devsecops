"""Stages shared by every entry point: preparation (SARIF + diff + clusters) and report output."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from secagent.context.diff import PrDiff, load_diff
from secagent.context.redact import redact, redact_value
from secagent.context.sarif import (
    Cluster,
    ScanFinding,
    cluster_findings,
    filter_changed,
    load_findings,
)
from secagent.models import Report
from secagent.report.github import build_review
from secagent.report.markdown import render_markdown
from secagent.report.sarif_out import to_sarif
from secagent.tools.fs import RepoFS, ToolError
from secagent.trace import Trace


@dataclass
class Prepared:
    repo: Path
    findings: list[ScanFinding]
    sarif_errors: list[str]
    secret_lines: dict[str, set[int]]
    diff: PrDiff
    relevant: list[ScanFinding]
    clusters: list[Cluster]
    fs: RepoFS
    requirements: str | None


def _requirements(fs: RepoFS, raw: str, use_requirements: bool, trace: Trace) -> str | None:
    """The business rules, read inside the repository (no symlink out of it) and redacted."""
    if not use_requirements:
        return None
    path = Path(raw)
    if path.is_absolute():
        try:
            raw = path.resolve().relative_to(fs.root).as_posix()
        except ValueError:
            trace.event("requirements_outside_repo", path=str(path))
            return None
    try:
        return redact("\n".join(fs.lines(raw)))
    except ToolError as exc:
        trace.event("requirements_unavailable", path=raw, error=str(exc))
        return None


def head_reader(repo: Path, rev: str) -> Callable[[str], list[str] | None]:
    """Lines of a file at the PR head commit (suggestions are anchored there), or None."""
    def read(path: str) -> list[str] | None:
        done = subprocess.run(["git", "-C", str(repo), "show", f"{rev}:{path}"],
                              capture_output=True, check=False)
        if done.returncode != 0:
            return None
        return done.stdout.decode("utf-8", errors="replace").splitlines()
    return read


def prepare(repo: Path, base: str, head: str, sarif_dir: Path, requirements_path: str,
            use_requirements: bool, trace: Trace) -> Prepared:
    findings, errors = load_findings(sarif_dir)
    secret_lines: dict[str, set[int]] = {}
    for f in findings:
        if f.tool == "gitleaks" and f.file:
            secret_lines.setdefault(f.file, set()).update(range(f.line, f.end_line + 1))
    diff = load_diff(repo, base, head).mask_lines(secret_lines)
    # Judge exactly the findings the quality gate considers (its changed-file filter).
    relevant = filter_changed(findings, diff.changed)
    clusters = cluster_findings(relevant, diff)
    fs = RepoFS(repo, secret_lines)
    return Prepared(repo=repo, findings=findings, sarif_errors=errors, secret_lines=secret_lines,
                    diff=diff, relevant=relevant, clusters=clusters, fs=fs,
                    requirements=_requirements(fs, requirements_path, use_requirements, trace))


def write_outputs(raw: Report, prepared: Prepared, out: Path, head: str) -> Report:
    """Redact the whole report, write report.json/report.md/agent.sarif/review.json, return it."""
    # Defence in depth: whatever the model wrote, no secret-shaped string leaves the run.
    report = Report.model_validate(redact_value(raw.model_dump(mode="json")))
    (out / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(report, head_sha=head), encoding="utf-8")
    (out / "agent.sarif").write_text(json.dumps(to_sarif(report), indent=2, ensure_ascii=False),
                                     encoding="utf-8")
    review = build_review(report, prepared.diff, head, head_reader(prepared.repo, head))
    if review is not None:
        (out / "review.json").write_text(json.dumps(review, indent=2, ensure_ascii=False),
                                         encoding="utf-8")
    return report
