"""Scanner SARIF → findings → clusters (spec 4.1 phase 0, roadmap Contract 2).

Finding ids and severities must be byte-for-byte those of security/gate/gate.py: the gate
matches report.json → finding_ids against its own ids. normalize_path, severity_of and the rule
lookup below are ports of the gate's functions; tests/test_sarif.py compares both on every
SARIF fixture of the gate so the two cannot drift silently.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from secagent.context.diff import PrDiff
from secagent.context.redact import redact
from secagent.models import SEVERITY_RANK

_LEVELS = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
_WORKSPACE_PREFIXES = ("/github/workspace/",)
_CWE = re.compile(r"(?i)cwe[-_/ ]?0*(\d+)")
DEFAULT_CWES = {"gitleaks": ("CWE-798",), "trivy": ("CWE-1395",)}
COMMIT_SCOPED = frozenset({"gitleaks"})  # scans the PR's commits, not the tree diff


def _group(*numbers: int) -> frozenset[str]:
    return frozenset(f"CWE-{n}" for n in numbers)


CWE_GROUPS: dict[str, frozenset[str]] = {
    "sql": _group(89, 564, 943),
    "command": _group(77, 78),
    "code": _group(94, 95, 1336),
    "xss": _group(79, 80, 116),
    "path": _group(22, 23, 35, 73),
    "deserialization": _group(502),
    "xxe": _group(611, 776),
    "ssrf": _group(918),
    "secret": _group(259, 321, 522, 798),
    "crypto": _group(327, 328, 330, 338),
    "logging": _group(117, 312, 359, 532),
    "authz": _group(284, 285, 639, 862, 863),
    "authn": _group(287, 306, 345, 347),
}


@dataclass(frozen=True)
class ScanFinding:
    tool: str
    rule_id: str
    severity: str
    file: str
    line: int
    end_line: int
    message: str
    cwes: tuple[str, ...]
    related: tuple[str, ...]

    @property
    def id(self) -> str:
        return f"{self.tool}:{self.rule_id}:{self.file}:{self.line}"


def normalize_path(uri: str, workspace: str | None) -> str:
    path = uri.replace("\\", "/")
    path = unquote(path.removeprefix("file://"))
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
        return "HIGH"
    rule = rule or {}
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        sev = _score_to_severity(props.get("security-severity"))
        if sev:
            return sev
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return _LEVELS.get(level or "", "LOW")


def _components(tool: dict) -> list[list[dict]]:
    driver = (tool.get("driver") or {}).get("rules") or []
    extensions = [(ext or {}).get("rules") or [] for ext in tool.get("extensions") or []]
    return [driver, *extensions]


def _rule_for(result: dict, tool: dict) -> tuple[str, dict | None]:
    components = _components(tool)
    ref = result.get("rule") or {}
    rule_id = result.get("ruleId") or ref.get("id")
    index = result.get("ruleIndex", ref.get("index"))
    component = (ref.get("toolComponent") or {}).get("index")
    in_range = isinstance(component, int) and 0 <= component < len(components) - 1
    rules = components[component + 1] if in_range else components[0]
    rule = None
    if isinstance(index, int) and 0 <= index < len(rules):
        rule = rules[index]
    if rule is None or (rule_id and rule.get("id") != rule_id):
        rule = next((r for rs in components for r in rs
                     if isinstance(r, dict) and r.get("id") == rule_id), None)
    if rule_id is None and rule is not None:
        rule_id = rule.get("id")
    return (rule_id or "unknown"), rule


def _location(result: dict, workspace: str | None) -> tuple[str, int, int]:
    for loc in result.get("locations") or []:
        physical = (loc or {}).get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        if uri:
            region = physical.get("region") or {}
            line = int(region.get("startLine") or 0)
            return normalize_path(uri, workspace), line, int(region.get("endLine") or line)
    return "", 0, 0


def _related_files(result: dict, workspace: str | None) -> set[str]:
    physical = [(loc or {}).get("physicalLocation") for loc in result.get("relatedLocations") or []]
    for flow in result.get("codeFlows") or []:
        for thread in (flow or {}).get("threadFlows") or []:
            for step in (thread or {}).get("locations") or []:
                physical.append(((step or {}).get("location") or {}).get("physicalLocation"))
    uris = (((p or {}).get("artifactLocation") or {}).get("uri") for p in physical)
    return {normalize_path(uri, workspace) for uri in uris if uri}


def _cwes(result: dict, rule: dict | None, tool: str) -> tuple[str, ...]:
    blob = json.dumps((rule or {}).get("properties") or {}) + json.dumps(
        result.get("properties") or {})
    found = sorted({f"CWE-{int(n)}" for n in _CWE.findall(blob)}, key=lambda c: int(c[4:]))
    return tuple(found) or DEFAULT_CWES.get(tool, ())


def _message(result: dict, rule_id: str, tool: str) -> str:
    if tool == "gitleaks":
        return f"Gitleaks: {rule_id}"  # never forward Gitleaks text: it may quote the secret
    text = (result.get("message") or {}).get("text") or ""
    return redact(text)[:300]


def _load_sarif(path: Path, tool: str, workspace: str | None) -> list[ScanFinding]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for run in doc["runs"] or []:
        tool_meta = run.get("tool") or {}
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id, rule = _rule_for(result, tool_meta)
            file, line, end_line = _location(result, workspace)
            findings.append(ScanFinding(
                tool=tool, rule_id=rule_id, severity=severity_of(result, rule, tool),
                file=file, line=line, end_line=max(end_line, line),
                message=_message(result, rule_id, tool), cwes=_cwes(result, rule, tool),
                related=tuple(sorted(_related_files(result, workspace) - {file})),
            ))
    return findings


def load_findings(sarif_dir: Path, workspace: str | None = None,
                  ) -> tuple[list[ScanFinding], list[str]]:
    """Every *.sarif in the directory; the tool name is the file stem (like the gate)."""
    sarif_dir = Path(sarif_dir)
    if not sarif_dir.is_dir():
        return [], []
    findings: list[ScanFinding] = []
    errors: list[str] = []
    for path in sorted(sarif_dir.glob("*.sarif")):
        try:
            findings.extend(_load_sarif(path, path.stem, workspace))
        except (OSError, ValueError, KeyError, TypeError):
            errors.append(path.name)
    return findings, errors


_TF_SUFFIXES = (".tf", ".tfvars", ".tf.json")


def _tf_dir(path: str) -> str | None:
    return posixpath.dirname(path) if path.endswith(_TF_SUFFIXES) else None


def filter_changed(findings: list[ScanFinding], changed: set[str]) -> list[ScanFinding]:
    """The findings the quality gate considers (port of gate.filter_changed): location-less,
    commit-scoped (Gitleaks), any location in a changed file, or the same Terraform module."""
    tf_dirs = {d for d in map(_tf_dir, changed) if d is not None}

    def keep(f: ScanFinding) -> bool:
        if f.file == "" or f.tool in COMMIT_SCOPED:
            return True
        if f.file in changed or any(p in changed for p in f.related):
            return True
        return _tf_dir(f.file) in tf_dirs

    return [f for f in findings if keep(f)]


@dataclass
class Cluster:
    """Findings of one or more tools that describe the same issue (file, ±3 lines, CWE group)."""

    id: str
    findings: list[ScanFinding]
    in_diff: bool = False

    @property
    def ids(self) -> list[str]:
        return sorted(f.id for f in self.findings)

    @property
    def file(self) -> str:
        return self.findings[0].file

    @property
    def line(self) -> int:
        return min(f.line for f in self.findings)

    @property
    def end_line(self) -> int:
        return max(f.end_line for f in self.findings)

    @property
    def severity(self) -> str:
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_RANK.get(s, 0))

    @property
    def cwes(self) -> list[str]:
        return sorted({c for f in self.findings for c in f.cwes}, key=lambda c: int(c[4:]))

    @property
    def tools(self) -> list[str]:
        return sorted({f.tool for f in self.findings})


def cwe_group(cwe: str) -> str:
    """The CWE family name (e.g. "sql"), or the CWE itself when it has no family."""
    return next((name for name, members in CWE_GROUPS.items() if cwe in members), cwe)


def group_keys(finding: ScanFinding) -> set[str]:
    if not finding.cwes:
        return {f"rule:{finding.rule_id}"}
    return {cwe_group(cwe) for cwe in finding.cwes}


def _in_diff(members: list[ScanFinding], diff: PrDiff) -> bool:
    for f in members:
        if f.tool in COMMIT_SCOPED:
            return True
        changed = diff.files.get(f.file)
        if changed is not None and (f.line <= 1 or f.line in changed.added):
            return True
    return False


def cluster_findings(findings: list[ScanFinding], diff: PrDiff) -> list[Cluster]:
    groups: list[list[ScanFinding]] = []
    for finding in sorted(findings, key=lambda f: (f.file, f.line, f.tool, f.rule_id)):
        keys = group_keys(finding)
        target = None
        if finding.file:
            for group in groups:
                if (group[0].file == finding.file
                        and any(abs(m.line - finding.line) <= 3 for m in group)
                        and keys & set().union(*(group_keys(m) for m in group))):
                    target = group
                    break
        if target is None:
            groups.append([finding])
        else:
            target.append(finding)
    return [Cluster(f"F{i}", members, _in_diff(members, diff))
            for i, members in enumerate(groups, start=1)]
