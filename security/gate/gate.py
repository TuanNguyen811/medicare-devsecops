"""Security quality gate for Pull Requests (standard library only).

Reads the SARIF files written by the scanners (and, in ai-assisted mode, the AI agent's
report.json) and decides whether the PR is blocked. Contract: roadmap "Hợp đồng 2".

    python security/gate/gate.py --sarif-dir sarif (--base SHA --head SHA | --changed-files F) \
        --mode traditional|ai-assisted [--report out/report.json] [--agent-exit N] \
        [--labels a,b] [--workspace DIR] [--summary FILE]

--base/--head: changed files = git diff from the merge base (run inside the repo).
--changed-files: one path per line, or NUL-separated (git diff --name-only -z).
Gitleaks findings skip the changed-file filter, so Gitleaks must scan the PR's commits only
(git mode with --log-opts BASE..HEAD), never the whole tree, when a filter is used.

Exit code 1 = blocked, 0 = pass.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BLOCKING = {"HIGH", "CRITICAL"}
REVIEWED_LABEL = "security-reviewed"
AGENT_CONFIDENCE = 0.7
_LEVELS = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
_WORKSPACE_PREFIXES = ("/github/workspace/",)
# Tools that scan the PR's commits (not the tree): the path is the one of the commit that added
# the finding, which a later commit may rename or delete, so the tree diff must not filter it.
COMMIT_SCOPED = frozenset({"gitleaks"})
_TF_SUFFIXES = (".tf", ".tfvars", ".tf.json")
# Changing these needs the security-reviewed label: scanner config, the gate, the workflows,
# the AI agent (its verdicts can unblock findings in ai-assisted mode), and every ignore
# file a scanner would honour.
SENSITIVE_PREFIXES = (".github/", "security/", "agent/")
SUPPRESSION_FILES = frozenset({
    ".semgrepignore", ".trivyignore", ".trivyignore.yaml", "trivy.yaml", "trivy.yml",
    ".gitleaksignore", ".gitleaks.toml", ".checkov.yaml", ".checkov.yml", ".bandit",
    "zizmor.yml", "zizmor.yaml",
})


class SarifError(ValueError):
    """A SARIF file could not be read; the gate must not pass blindly."""


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: str
    file: str
    line: int
    # Other files on the finding (related locations, code-flow steps); not part of the id.
    related: tuple[str, ...] = field(default=(), compare=False, repr=False)

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
    path = unquote(path.removeprefix("file://"))  # SARIF uris are percent-encoded
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


def _components(tool: dict) -> list[list[dict]]:
    """Rule lists of the driver (component -1) and of each extension (CodeQL query packs)."""
    driver = (tool.get("driver") or {}).get("rules") or []
    extensions = [(ext or {}).get("rules") or [] for ext in tool.get("extensions") or []]
    return [driver, *extensions]


def _rule_for(result: dict, tool: dict) -> tuple[str, dict | None]:
    components = _components(tool)
    ref = result.get("rule") or {}
    rule_id = result.get("ruleId") or ref.get("id")
    index = result.get("ruleIndex", ref.get("index"))
    # SARIF: rule.toolComponent.index points into tool.extensions; absent means the driver.
    component = (ref.get("toolComponent") or {}).get("index")
    rules = components[component + 1] if isinstance(component, int) and \
        0 <= component < len(components) - 1 else components[0]
    rule = None
    if isinstance(index, int) and 0 <= index < len(rules):
        rule = rules[index]
    if rule is None or (rule_id and rule.get("id") != rule_id):
        rule = next((r for rs in components for r in rs
                     if isinstance(r, dict) and r.get("id") == rule_id), None)
    if rule_id is None and rule is not None:
        rule_id = rule.get("id")
    return (rule_id or "unknown"), rule


def _location(result: dict, workspace: str | None) -> tuple[str, int]:
    for loc in result.get("locations") or []:
        physical = (loc or {}).get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        if uri:
            line = (physical.get("region") or {}).get("startLine") or 0
            return normalize_path(uri, workspace), int(line)
    return "", 0


def _related_files(result: dict, workspace: str | None) -> set[str]:
    physical = [(loc or {}).get("physicalLocation") for loc in result.get("relatedLocations") or []]
    for flow in result.get("codeFlows") or []:
        for thread in (flow or {}).get("threadFlows") or []:
            for step in (thread or {}).get("locations") or []:
                physical.append(((step or {}).get("location") or {}).get("physicalLocation"))
    uris = (((p or {}).get("artifactLocation") or {}).get("uri") for p in physical)
    return {normalize_path(uri, workspace) for uri in uris if uri}


def load_sarif(path: Path, tool: str, workspace: str | None) -> list[Finding]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        runs = doc["runs"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SarifError(f"{Path(path).name}: {type(exc).__name__}") from exc
    findings = []
    for run in runs or []:
        tool_meta = run.get("tool") or {}
        for result in run.get("results") or []:
            rule_id, rule = _rule_for(result, tool_meta)
            file, line = _location(result, workspace)
            related = tuple(sorted(_related_files(result, workspace) - {file}))
            findings.append(Finding(tool, rule_id, severity_of(result, rule, tool), file, line,
                                    related))
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


def changed_from_git(base: str, head: str, repo: str | Path = ".") -> set[str]:
    """Files the PR changed: diff from the merge base of base and head (three dots), so commits
    that landed on main after the PR branched are not counted. Renames count as both paths."""
    if base.startswith("-") or head.startswith("-"):
        raise ValueError("base/head must be commits, not options")
    out = subprocess.run(
        ["git", "-C", str(repo), "-c", "core.quotePath=false", "diff", "--name-only",
         "--no-renames", "-z", f"{base}...{head}"],
        check=True, capture_output=True,
    ).stdout
    return {p for p in out.decode("utf-8").split("\0") if p}


def _read_changed(path: str) -> set[str]:
    raw = Path(path).read_text(encoding="utf-8")
    names = raw.split("\0") if "\0" in raw else [x.strip() for x in raw.splitlines()]
    return {x.replace("\\", "/") for x in names if x}


def _tf_dir(path: str) -> str | None:
    return posixpath.dirname(path) if path.endswith(_TF_SUFFIXES) else None


def filter_changed(findings: list[Finding], changed: set[str]) -> list[Finding]:
    """Keep the findings the PR can have caused:
    - location-less findings, and findings of commit-scoped tools (Gitleaks);
    - any location (primary, related, code-flow step) in a changed file;
    - a Terraform finding when any file of the same module directory changed (Checkov
      evaluates variables, so editing variables.tf surfaces findings in main.tf)."""
    tf_dirs = {d for d in map(_tf_dir, changed) if d is not None}

    def keep(x: Finding) -> bool:
        if x.file == "" or x.tool in COMMIT_SCOPED:
            return True
        if x.file in changed or any(p in changed for p in x.related):
            return True
        return _tf_dir(x.file) in tf_dirs

    return [x for x in findings if keep(x)]


def sensitive_paths(changed: set[str]) -> list[str]:
    return sorted(p for p in changed if p.startswith(SENSITIVE_PREFIXES)
                  or posixpath.basename(p) in SUPPRESSION_FILES)


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
    changed: set[str] | None = None,
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
    sensitive = sensitive_paths(changed or set())
    if sensitive and REVIEWED_LABEL in labels:
        decision.notes.append(f"PR sửa cấu hình bảo mật/pipeline, đã có label `{REVIEWED_LABEL}`: "
                              + ", ".join(sensitive))
    elif sensitive:
        decision.block = True
        decision.blocking += [f"policy:{p}" for p in sensitive]
        decision.notes.append(f"PR sửa cấu hình bảo mật/pipeline: cần label `{REVIEWED_LABEL}` "
                              "sau khi người review bảo mật đã xem.")
    return decision


def _ai_assisted(findings: list[Finding], report: dict, labels: set[str]) -> Decision:
    verdicts: dict[str, dict] = {}
    entries = [e for e in report.get("findings") or [] if isinstance(e, dict)]
    for entry in entries:
        for fid in entry.get("finding_ids") or []:
            previous = verdicts.get(fid)
            if previous is None or previous.get("verdict") == "FP":  # any non-FP verdict wins
                verdicts[fid] = entry
    decision = Decision(False, "ai-assisted")
    for item in findings:
        if item.severity not in BLOCKING:
            continue
        entry = verdicts.get(item.id)
        verdict = (entry or {}).get("verdict")
        if verdict != "FP" or (item.severity == "CRITICAL" and REVIEWED_LABEL not in labels):
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
    p.add_argument("--base")
    p.add_argument("--head")
    p.add_argument("--mode", choices=("traditional", "ai-assisted"), default="traditional")
    p.add_argument("--report")
    p.add_argument("--agent-exit", type=int)
    p.add_argument("--labels", default="")
    p.add_argument("--workspace")
    p.add_argument("--summary")
    args = p.parse_args(argv)

    if bool(args.base) != bool(args.head):
        p.error("--base and --head go together")
    findings, errors = load_all(Path(args.sarif_dir), args.workspace)
    changed = None
    if args.base:
        changed = changed_from_git(args.base, args.head)
    elif args.changed_files:
        changed = _read_changed(args.changed_files)
    if changed is not None:
        findings = filter_changed(findings, changed)
    labels = {x.strip() for x in args.labels.split(",") if x.strip()}
    decision = decide(findings, mode=args.mode, report=_read_report(args.report), labels=labels,
                      agent_exit=args.agent_exit, errors=errors, changed=changed)
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
