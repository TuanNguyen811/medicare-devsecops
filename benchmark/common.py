"""Shared by pr_bench.py and evaluate.py: paths, the quality gate module, what the gate and the
agent see for a PR's scanner results, the agent version, and run classification."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import scenario as sc

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = HERE / "results"
SCANNERS = ("codeql", "semgrep", "bandit", "trivy", "gitleaks", "checkov", "zizmor")
USAGE_WAIT_S = 15 * 60
USAGE_MAX_WAITS = 24  # six hours


def load_gate():
    spec = importlib.util.spec_from_file_location("gate", ROOT / "security" / "gate" / "gate.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["gate"] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


def _cluster_json(clusters) -> list[dict]:
    return [{"id": c.id, "file": c.file, "line": c.line, "end_line": c.end_line,
             "severity": c.severity, "tools": c.tools, "cwes": c.cwes, "finding_ids": c.ids,
             "rules": sorted({f.rule_id for f in c.findings}), "in_diff": c.in_diff}
            for c in clusters]


def scan_views(scenario_dir: Path, gate) -> None:
    """What the gate and the agent see for C1 (scanners, no ZAP) and C1+DAST, computed on the
    PR's own commits (scenario.json: id, base, head, pr) from the SARIF in scenario_dir:
    changed.json, clusters.json, gate.json (traditional decisions), gate_findings.json."""
    from secagent.stages import prepare
    from secagent.trace import Trace

    meta = json.loads((scenario_dir / "scenario.json").read_text(encoding="utf-8"))
    work = Path(tempfile.mkdtemp(prefix="bench-views-"))
    repo = work / "repo"
    try:
        subprocess.run(["git", "fetch", "--quiet", "origin", meta["base"],
                        f"pull/{meta['pr']}/head"], cwd=ROOT, check=True)
        subprocess.run(["git", "worktree", "add", "--quiet", "--detach", str(repo),
                        meta["head"]], cwd=ROOT, check=True)
        changed = sorted(gate.changed_from_git(meta["base"], meta["head"], repo))
        (scenario_dir / "changed.json").write_text(json.dumps(changed, indent=2),
                                                   encoding="utf-8")
        views, decisions, gate_findings = {}, {}, {}
        for view in ("C1", "C1+DAST"):
            sarif = work / view.replace("+", "_")
            sarif.mkdir()
            for path in scenario_dir.glob("*.sarif"):
                if view == "C1+DAST" or path.stem != "zap":
                    shutil.copy(path, sarif / path.name)
            prep = prepare(repo, meta["base"], meta["head"], sarif,
                           "docs/security-requirements.md", False, Trace(None))
            if prep.sarif_errors:
                raise sc.ScenarioError(f"{meta['id']}: unreadable SARIF {prep.sarif_errors}")
            views[view] = _cluster_json(prep.clusters)
            findings, errors = gate.load_all(sarif, None)
            relevant = gate.filter_changed(findings, set(changed))
            gate_findings[view] = {"errors": errors,
                                   "findings": [{"id": x.id, "severity": x.severity}
                                                for x in relevant]}
            decision = gate.decide(relevant, mode="traditional", report=None, labels=set(),
                                   agent_exit=None, errors=errors, changed=set(changed))
            decisions[view] = {"block": decision.block, "blocking": decision.blocking}
        (scenario_dir / "clusters.json").write_text(json.dumps(views, indent=2),
                                                    encoding="utf-8")
        (scenario_dir / "gate.json").write_text(json.dumps(decisions, indent=2),
                                                encoding="utf-8")
        # What the gate needs to judge an agent report later, without the (large) SARIF files.
        (scenario_dir / "gate_findings.json").write_text(json.dumps(gate_findings, indent=2),
                                                         encoding="utf-8")
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(repo)], cwd=ROOT,
                       check=False, capture_output=True)
        shutil.rmtree(work, ignore_errors=True)


def agent_version() -> dict:
    """The secagent code that produced a run: the git tree of agent/ (prompts included; it
    changes only when agent/ does), and whether agent/ had uncommitted edits."""
    commit = subprocess.run(["git", "rev-parse", "HEAD:agent"], cwd=ROOT, capture_output=True,
                            text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "agent"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.strip()
    return {"agent_commit": commit, "agent_dirty": bool(dirty)}


_LIMIT = re.compile(r"claude-mcp: (usage-limit|[^\n]*(limit|quota|\b429\b))", re.IGNORECASE)
_AUTH = re.compile(r"claude-mcp: auth", re.IGNORECASE)


def classify(rundir: Path) -> str | None:
    """'usage-limit' or 'auth' when Claude Code could not run, whether secagent failed or
    stopped midway (meta.error)."""
    text = ""
    report = rundir / "report.json"
    if report.is_file():
        meta = json.loads(report.read_text(encoding="utf-8")).get("meta") or {}
        text += str(meta.get("error") or "")
    else:
        for name in ("report.md", "trace.jsonl"):
            path = rundir / name
            if path.is_file():
                text += path.read_text(encoding="utf-8", errors="replace")
    if _AUTH.search(text):
        return "auth"
    if _LIMIT.search(text):
        return "usage-limit"
    return None
