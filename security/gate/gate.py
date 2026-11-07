"""Security quality gate for Pull Requests (standard library only).

Reads the SARIF files written by the scanners (and, in ai-assisted mode, the AI agent's
report.json) and decides whether the PR is blocked. Contract: roadmap "Hợp đồng 2".

    python security/gate/gate.py --sarif-dir sarif --changed-files changed.txt \
        --mode traditional|ai-assisted [--report out/report.json] [--agent-exit N] \
        [--labels a,b] [--workspace DIR] [--summary FILE]

Exit code 1 = blocked, 0 = pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BLOCKING = {"HIGH", "CRITICAL"}
REVIEWED_LABEL = "security-reviewed"
AGENT_CONFIDENCE = 0.7
_LEVELS = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
_WORKSPACE_PREFIXES = ("/github/workspace/",)


class SarifError(ValueError):
    """A SARIF file could not be read; the gate must not pass blindly."""


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: str
    file: str
    line: int

    @property
    def id(self) -> str:
        return f"{self.tool}:{self.rule_id}:{self.file}:{self.line}"


@dataclass
class Decision:
    block: bool
    mode_used: str
    blocking: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def normalize_path(uri: str, workspace: str | None) -> str:
    path = uri.replace("\\", "/")
    path = path.removeprefix("file://")
    prefixes = list(_WORKSPACE_PREFIXES)
    if workspace:
        prefixes.insert(0, workspace.replace("\\", "/").rstrip("/") + "/")
    for prefix in prefixes:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    while path.startswith("./"):
        path = path[2:]
    return path


def _score_to_severity(raw) -> str | None:
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def severity_of(result: dict, rule: dict | None, tool: str) -> str:
    if tool == "gitleaks":
        return "HIGH"  # any committed secret is high impact
    rule = rule or {}
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        sev = _score_to_severity(props.get("security-severity"))
        if sev:
            return sev
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return _LEVELS.get(level or "", "LOW")


def _rule_for(result: dict, rules: list[dict]) -> tuple[str, dict | None]:
    by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
    ref = result.get("rule") or {}
    rule_id = result.get("ruleId") or ref.get("id")
    index = result.get("ruleIndex", ref.get("index"))
    if rule_id is None and isinstance(index, int) and 0 <= index < len(rules):
        rule_id = rules[index].get("id")
    return (rule_id or "unknown"), by_id.get(rule_id)


def _location(result: dict, workspace: str | None) -> tuple[str, int]:
    for loc in result.get("locations") or []:
        physical = (loc or {}).get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        if uri:
            line = (physical.get("region") or {}).get("startLine") or 0
            return normalize_path(uri, workspace), int(line)
    return "", 0


def load_sarif(path: Path, tool: str, workspace: str | None) -> list[Finding]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        runs = doc["runs"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SarifError(f"{Path(path).name}: {type(exc).__name__}") from exc
    findings = []
    for run in runs or []:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        for result in run.get("results") or []:
            rule_id, rule = _rule_for(result, rules)
            file, line = _location(result, workspace)
            findings.append(Finding(tool, rule_id, severity_of(result, rule, tool), file, line))
    return findings


def load_all(sarif_dir: Path, workspace: str | None) -> tuple[list[Finding], list[str]]:
    sarif_dir = Path(sarif_dir)
    if not sarif_dir.is_dir():
        return [], []
    findings, errors = [], []
    for path in sorted(sarif_dir.glob("*.sarif")):
        try:
            findings.extend(load_sarif(path, path.stem, workspace))
        except SarifError:
            errors.append(path.name)
    return findings, errors


def filter_changed(findings: list[Finding], changed: set[str]) -> list[Finding]:
    """Keep findings in files the PR touched; location-less findings always stay."""
    return [x for x in findings if x.file == "" or x.file in changed]


def _traditional(findings: list[Finding], mode_used: str) -> Decision:
    blocking = [x.id for x in findings if x.severity in BLOCKING]
    return Decision(bool(blocking), mode_used, blocking)


def decide(
    findings: list[Finding],
    *,
    mode: str,
    report: dict | None,
    labels: set[str],
    agent_exit: int | None,
    errors: list[str],
) -> Decision:
    if mode != "ai-assisted":
        decision = _traditional(findings, "traditional")
    elif agent_exit != 0 or report is None:
        decision = _traditional(findings, "traditional (fallback)")
    else:
        decision = _ai_assisted(findings, report, labels)
    if errors:
        decision.block = True
        decision.notes.append("Không đọc được SARIF: " + ", ".join(errors))
    return decision


def _ai_assisted(findings: list[Finding], report: dict, labels: set[str]) -> Decision:
    verdicts: dict[str, dict] = {}
    entries = [e for e in report.get("findings") or [] if isinstance(e, dict)]
    for entry in entries:
        for fid in entry.get("finding_ids") or []:
            verdicts[fid] = entry
    decision = Decision(False, "ai-assisted")
    for item in findings:
        if item.severity not in BLOCKING:
            continue
        entry = verdicts.get(item.id)
        verdict = (entry or {}).get("verdict")
        if entry is None or verdict in ("TP", "NEEDS_REVIEW") or verdict != "FP" or item.severity == "CRITICAL" and REVIEWED_LABEL not in labels:
            decision.blocking.append(item.id)
        else:
            decision.notes.append(f"Agent kết luận FP: {item.id}")
    for entry in entries:
        if (
            entry.get("source") == "agent"
            and entry.get("verdict") == "TP"
            and entry.get("severity") in BLOCKING
            and float(entry.get("confidence") or 0) >= AGENT_CONFIDENCE
        ):
            decision.blocking.append(f"agent:{entry.get('title') or entry.get('cwe') or 'finding'}")
    decision.block = bool(decision.blocking)
    return decision


def render_summary(decision: Decision, findings: list[Finding]) -> str:
    """Markdown summary. Never includes SARIF messages (they may contain secrets)."""
    tools = sorted({x.tool for x in findings})
    lines = [
        "## Security quality gate",
        "",
        f"**Kết quả:** {'❌ CHẶN' if decision.block else '✅ ĐẠT'} · **Chế độ:** {decision.mode_used}",
        "",
        "| Công cụ | " + " | ".join(SEVERITIES) + " |",
        "|---|" + "---|" * len(SEVERITIES),
    ]
    for tool in tools:
        counts = [sum(1 for x in findings if x.tool == tool and x.severity == s)
                  for s in SEVERITIES]
        lines.append(f"| {tool} | " + " | ".join(str(c) for c in counts) + " |")
    if not tools:
        lines.append("| (không có phát hiện) |" + " |" * len(SEVERITIES))
    by_id = {x.id: x for x in findings}
    if decision.blocking:
        lines += ["", "### Phát hiện bị chặn", ""]
        for fid in decision.blocking:
            x = by_id.get(fid)
            lines.append(f"- `{x.tool}` · `{x.rule_id}` · `{x.file}:{x.line}` · {x.severity}"
                         if x else f"- `{fid}`")
    if decision.notes:
        lines += ["", "### Ghi chú", ""] + [f"- {n}" for n in decision.notes]
    return "\n".join(lines) + "\n"


def _read_report(path: str | None) -> dict | None:
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--sarif-dir", default="sarif")
    p.add_argument("--changed-files")
    p.add_argument("--mode", choices=("traditional", "ai-assisted"), default="traditional")
    p.add_argument("--report")
    p.add_argument("--agent-exit", type=int)
    p.add_argument("--labels", default="")
    p.add_argument("--workspace")
    p.add_argument("--summary")
    args = p.parse_args(argv)

    findings, errors = load_all(Path(args.sarif_dir), args.workspace)
    if args.changed_files:
        changed = {
            line.strip().replace("\\", "/")
            for line in Path(args.changed_files).read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        findings = filter_changed(findings, changed)
    labels = {x.strip() for x in args.labels.split(",") if x.strip()}
    decision = decide(findings, mode=args.mode, report=_read_report(args.report), labels=labels,
                      agent_exit=args.agent_exit, errors=errors)
    summary = render_summary(decision, findings)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # same bytes on Linux CI and Windows dev
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(summary)
    sys.stdout.write(summary)
    return 1 if decision.block else 0


if __name__ == "__main__":
    sys.exit(main())
