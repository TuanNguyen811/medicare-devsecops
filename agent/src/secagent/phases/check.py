"""Phase 2: deterministic checks after the review session (spec 4.1).

- Coverage: clusters without a verdict get one follow-up request; still missing → NEEDS_REVIEW.
- Anti-hallucination: cited evidence must exist in the repository; otherwise → NEEDS_REVIEW.
  An FP verdict must cite evidence. Nothing here can ever turn a finding into FP.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable

from secagent.config import Settings
from secagent.context.sarif import Cluster, ScanFinding, cwe_group, group_keys
from secagent.models import SEVERITY_RANK, Evidence, ReportEntry
from secagent.phases.review import ReviewOutcome, budget_left
from secagent.tools.fs import RepoFS, ToolError
from secagent.trace import Trace

TOOL_ORDER = ("semgrep", "codeql", "bandit", "trivy", "gitleaks", "checkov", "zizmor")
VERDICT_ORDER = {"TP": 0, "NEEDS_REVIEW": 1, "FP": 2}
_LINE_PREFIX = re.compile(r"^\s*\d+\|\s?")  # a "   12| " prefix copied from read_file output


def ensure_coverage(outcome: ReviewOutcome, clusters: list[Cluster], settings: Settings,
                    clock: Callable[[], float] = time.monotonic) -> int:
    """Ask once for missing verdicts; returns how many clusters lacked one before asking."""
    missing_before = sum(1 for c in clusters if c.id not in outcome.verdicts)
    if (not missing_before or outcome.error is not None or outcome.limit_hit
            or settings.strategy == "single-shot"):
        return missing_before
    for session in outcome.sessions:
        missing = session.missing()
        if not missing:
            continue
        if outcome.error is not None or not budget_left(outcome, settings, clock):
            break
        session.ask_missing(missing, limit=2 + len(missing))
    return missing_before


def _normalize(text: str) -> str:
    return " ".join(_LINE_PREFIX.sub("", text).split())


def evidence_problems(evidence: list[Evidence], fs: RepoFS) -> list[str]:
    problems = []
    for item in evidence:
        try:
            lines = fs.lines(item.file)
        except ToolError as exc:
            problems.append(f"{item.file}: {exc}")
            continue
        if item.end_line > len(lines):
            problems.append(f"{item.file}:{item.start_line}-{item.end_line} vượt quá "
                            f"{len(lines)} dòng")
            continue
        window = [_normalize(line) for line in lines[max(0, item.start_line - 4):
                                                     item.end_line + 3]]
        for snippet_line in item.snippet.splitlines():
            wanted = _normalize(snippet_line)
            if wanted and not any(wanted in line for line in window):
                problems.append(f"{item.file}:{item.start_line} không có đoạn mã "
                                f"“{wanted[:60]}”")
                break
    return problems


def _tool_rank(tool: str) -> tuple[int, str]:
    return (TOOL_ORDER.index(tool) if tool in TOOL_ORDER else len(TOOL_ORDER), tool)


def _primary(cluster: Cluster) -> ScanFinding:
    return min(cluster.findings,
               key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), _tool_rank(f.tool), f.id))


def _uncovered_reason(cluster: Cluster, outcome: ReviewOutcome) -> str:
    if outcome.error is not None:
        cause = f"lỗi khi gọi LLM: {outcome.error}"
    elif outcome.limit_hit or cluster.id in outcome.unstarted:
        cause = "chạm giới hạn số bước, token hoặc thời gian"
    else:
        cause = "Agent bỏ sót phát hiện này"
    return f"Agent không đưa ra kết luận cho phát hiện này ({cause}); cần người review."


def _cluster_entry(cluster: Cluster, outcome: ReviewOutcome, fs: RepoFS) -> ReportEntry:
    primary = _primary(cluster)
    base = {"finding_id": primary.id, "finding_ids": cluster.ids, "source": primary.tool,
            "title": f"{primary.rule_id} ({primary.tool})", "file": cluster.file,
            "line": cluster.line}
    v = outcome.verdicts.get(cluster.id)
    if v is None:
        return ReportEntry(**base, verdict="NEEDS_REVIEW", confidence=0.0,
                           severity=cluster.severity,
                           cwe=cluster.cwes[0] if cluster.cwes else None,
                           reasoning=_uncovered_reason(cluster, outcome))
    verdict, reasoning = v.verdict, v.reasoning
    problems = evidence_problems(v.evidence, fs)
    if problems:
        verdict = "NEEDS_REVIEW"
        reasoning = f"[Bằng chứng không khớp mã nguồn: {'; '.join(problems)}] {reasoning}"
    elif v.verdict == "FP" and not v.evidence:
        verdict = "NEEDS_REVIEW"
        reasoning = f"[Kết luận FP không có bằng chứng] {reasoning}"
    return ReportEntry(**base, verdict=verdict, confidence=v.confidence, severity=v.severity,
                       cwe=v.cwe or (cluster.cwes[0] if cluster.cwes else None),
                       owasp=v.owasp, violated_rule=v.violated_rule, reasoning=reasoning,
                       evidence=v.evidence, exploit_scenario=v.exploit_scenario, fix=v.fix)


def _duplicate_of(file: str, line: int, cwe: str, clusters: list[Cluster]) -> Cluster | None:
    family = cwe_group(cwe)
    for cluster in clusters:
        if cluster.file != file:
            continue
        near = any(abs(f.line - line) <= 3 for f in cluster.findings)
        if near and family in set().union(*(group_keys(f) for f in cluster.findings)):
            return cluster
    return None


def build_entries(clusters: list[Cluster], outcome: ReviewOutcome, fs: RepoFS,
                  trace: Trace | None = None) -> list[ReportEntry]:
    entries = [_cluster_entry(c, outcome, fs) for c in clusters]
    kept = 0
    for found in outcome.new_findings:
        first = found.evidence[0]
        duplicate = _duplicate_of(first.file, first.start_line, found.cwe, clusters)
        if duplicate is not None:
            if trace is not None:
                trace.event("new_finding_dropped", title=found.title, duplicate_of=duplicate.id)
            continue
        kept += 1
        problems = evidence_problems(found.evidence, fs)
        reasoning = found.reasoning
        if problems:
            reasoning = f"[Bằng chứng không khớp mã nguồn: {'; '.join(problems)}] {reasoning}"
        entries.append(ReportEntry(
            finding_id=f"agent:{kept}", finding_ids=[], source="agent", title=found.title,
            verdict="NEEDS_REVIEW" if problems else "TP", confidence=found.confidence,
            severity=found.severity, cwe=found.cwe, owasp=found.owasp,
            violated_rule=found.violated_rule, reasoning=reasoning, evidence=found.evidence,
            exploit_scenario=found.exploit_scenario, fix=found.fix, file=first.file,
            line=first.start_line))
    return sorted(entries, key=lambda e: (VERDICT_ORDER[e.verdict],
                                          -SEVERITY_RANK.get(e.severity, 0), e.file, e.line))
