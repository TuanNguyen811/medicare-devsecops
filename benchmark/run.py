"""Run the benchmark (spec addendum 8.4): fetch CI scans, then run the agent on this machine.

    uv run --project agent --with pyyaml==6.0.2 python benchmark/run.py fetch --run <id>
    uv run --project agent --with pyyaml==6.0.2 python benchmark/run.py agent \\
        --config C2 --scan <id> --select dev --reps 1 --jobs 3 [--validate]

fetch    downloads the artifacts of a `Benchmark scan` workflow run into
         results/scans/<run>/<ID>/: the scanners' SARIF, zap.sarif (the five roles merged; a
         scenario that does not change what runs reuses S00's), and, computed here on the same
         scenario commits, what the quality gate sees: changed.json, clusters.json (C1 and
         C1+DAST), gate.json (traditional decisions) and gate_findings.json. The SARIF files
         stay out of git (large; the workflow run keeps them for 90 days).
agent    runs secagent (LLM mode claude-mcp) on every selected scenario x repetition, in a
         throwaway worktree that has no benchmark/ and no design documents, into
         results/runs/<config>/<ID>/rep<N>/. Runs already done are skipped; when the Claude plan's
         usage limit is reached it waits and retries.

The agent never reads this directory: its worktree, its prompt and its tools only reach the
scenario's code (benchmark/scenario.py).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import scenario as sc

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = HERE / "results"
CONFIGS = {  # spec addendum 8.3; every config runs secagent with LLM mode claude-mcp
    "C2": [],
    "C3": ["--strategy", "single-shot"],
    "C4": ["--no-requirements"],
    "C5": ["--no-ast-tools"],
}
SCANNERS = ("codeql", "semgrep", "bandit", "trivy", "gitleaks", "checkov", "zizmor")
USAGE_WAIT_S = 15 * 60
USAGE_MAX_WAITS = 24  # six hours
RUN_TIMEOUT_S = 1800
_git_lock = threading.Lock()  # git worktree add/remove on the same repository: one at a time


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _load_gate():
    spec = importlib.util.spec_from_file_location("gate", ROOT / "security" / "gate" / "gate.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["gate"] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


# --- fetch --------------------------------------------------------------------------------------


def _merge_zap(raw: Path, dest: Path, scenario_id: str) -> bool:
    """zap.sarif from the five role reports of a scenario; False when they are not all there."""
    reports, routes = [], None
    for role in sc.ROLES:
        folder = raw / f"dast-{scenario_id}-{role}"
        report = next(folder.rglob(f"zap-{role}.json"), None) if folder.is_dir() else None
        if report is None:
            return False
        reports.append(f"{role}={report}")
        routes = routes or next(folder.rglob("routes.json"), None)
    subprocess.run([sys.executable, str(ROOT / "security" / "dast" / "zap2sarif.py"),
                    "--routes", str(routes), "--out", str(dest / "zap.sarif"), *reports],
                   check=True)
    return True


def _cluster_json(clusters) -> list[dict]:
    return [{"id": c.id, "file": c.file, "line": c.line, "end_line": c.end_line,
             "severity": c.severity, "tools": c.tools, "cwes": c.cwes, "finding_ids": c.ids,
             "rules": sorted({f.rule_id for f in c.findings}), "in_diff": c.in_diff}
            for c in clusters]


def _scan_views(scenario_dir: Path, gate) -> None:
    """What the gate and the agent see for C1 (no ZAP) and C1+DAST, on the scenario commits."""
    from secagent.stages import prepare
    from secagent.trace import Trace

    meta = json.loads((scenario_dir / "scenario.json").read_text(encoding="utf-8"))
    (scenario,) = sc.select(meta["id"])
    work = Path(tempfile.mkdtemp(prefix="bench-fetch-"))
    try:
        with _git_lock:
            built = sc.materialize(scenario, work / "repo", ROOT)
        if (built["base"], built["head"]) != (meta["base"], meta["head"]):
            raise sc.ScenarioError(f"{meta['id']}: local commits differ from CI's: {built} "
                                   f"vs {meta}")
        repo = work / "repo"
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
        with _git_lock:
            subprocess.run(["git", "worktree", "remove", "--force", str(work / "repo")],
                           cwd=ROOT, check=False, capture_output=True)
        shutil.rmtree(work, ignore_errors=True)


def fetch(run_id: str, baseline_run: str | None) -> Path:
    out = RESULTS / "scans" / run_id
    raw = Path(tempfile.mkdtemp(prefix="bench-raw-"))
    try:
        subprocess.run(["gh", "run", "download", run_id, "--dir", str(raw)], check=True)
        gate = _load_gate()
        scanned = sorted(p.name.removeprefix("scan-") for p in raw.glob("scan-*"))
        if not scanned:
            raise sc.ScenarioError(f"run {run_id} has no scan-* artifact")
        for scenario_id in scanned:
            dest = out / scenario_id
            dest.mkdir(parents=True, exist_ok=True)
            for path in (raw / f"scan-{scenario_id}").iterdir():
                shutil.copy(path, dest / path.name)
            missing = [t for t in SCANNERS if not (dest / f"{t}.sarif").is_file()]
            if missing:
                raise sc.ScenarioError(f"{scenario_id}: missing SARIF {missing}")
            if not _merge_zap(raw, dest, scenario_id):
                (scenario,) = sc.select(scenario_id)
                if scenario.touches_app():
                    raise sc.ScenarioError(f"{scenario_id}: changes app/ but has no DAST")
                donor = _baseline_zap(out, baseline_run)
                shutil.copy(donor, dest / "zap.sarif")
                (dest / "zap.source").write_text(str(donor.parent.relative_to(RESULTS)),
                                                 encoding="utf-8")
        for scenario_id in scanned:
            _scan_views(out / scenario_id, gate)
            _say(f"fetch: {scenario_id} ok")
    finally:
        shutil.rmtree(raw, ignore_errors=True)
    return out


def _baseline_zap(out: Path, baseline_run: str | None) -> Path:
    for candidate in (out / sc.BASELINE / "zap.sarif",
                      RESULTS / "scans" / str(baseline_run) / sc.BASELINE / "zap.sarif"):
        if candidate.is_file():
            return candidate
    raise sc.ScenarioError("no S00 DAST to reuse: include S00 in the run or pass --baseline-run")


# --- agent ------------------------------------------------------------------------------------


def _done(rundir: Path) -> bool:
    timing = rundir / "timing.json"
    if not timing.is_file():
        return False
    return json.loads(timing.read_text(encoding="utf-8")).get("exit") == 0


def _classify(rundir: Path) -> str | None:
    """'usage-limit' or 'auth' when Claude Code refused to run, from the failure report."""
    text = ""
    for name in ("report.md", "trace.jsonl"):
        path = rundir / name
        if path.is_file():
            text += path.read_text(encoding="utf-8", errors="replace")
    for kind in ("usage-limit", "auth"):
        if f"claude-mcp: {kind}" in text:
            return kind
    return None


class Abort(Exception):
    pass


def run_one(config: str, scan: Path, scenario: sc.Scenario, rep: int, validate: bool,
            stop: threading.Event) -> str:
    rundir = RESULTS / "runs" / config / scenario.id / f"rep{rep}"
    if _done(rundir):
        return "skip"
    meta = json.loads((scan / scenario.id / "scenario.json").read_text(encoding="utf-8"))
    for attempt in range(USAGE_MAX_WAITS + 1):
        if stop.is_set():
            return "stopped"
        if rundir.exists():
            shutil.rmtree(rundir)
        rundir.mkdir(parents=True)
        work = Path(tempfile.mkdtemp(prefix="bench-run-"))
        repo = work / "repo"
        try:
            with _git_lock:
                built = sc.materialize(scenario, repo, ROOT)
            if built["head"] != meta["head"]:
                raise sc.ScenarioError(f"{scenario.id}: commits differ from the scan")
            env = {**os.environ, "LLM_PROVIDER": "claude-mcp", "PYTHONIOENCODING": "utf-8"}
            started = time.monotonic()
            cmd = ["uv", "run", "--project", str(ROOT / "agent"), "--locked", "secagent",
                   "--mode", "benchmark", "--repo", str(repo), "--base", meta["base"],
                   "--head", meta["head"], "--sarif-dir", str(scan / scenario.id),
                   "--requirements", "docs/security-requirements.md", "--out", str(rundir),
                   *CONFIGS[config]]
            done = subprocess.run(cmd, env=env, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=RUN_TIMEOUT_S,
                                  check=False)
            wall = round(time.monotonic() - started, 2)
            validated = None
            if done.returncode == 0 and validate:
                v = subprocess.run(["uv", "run", "--project", str(ROOT / "agent"), "--locked",
                                    "secagent-validate", "--out", str(rundir), "--repo",
                                    str(repo), "--head", meta["head"]],
                                   env=env, capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=RUN_TIMEOUT_S, check=False)
                validated = v.returncode
            (rundir / "timing.json").write_text(json.dumps({
                "config": config, "scenario": scenario.id, "rep": rep, "scan": scan.name,
                "exit": done.returncode, "wall_s": wall, "validate_exit": validated,
                "attempt": attempt, "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
            }, indent=2), encoding="utf-8")
            (rundir / "stderr.txt").write_text(done.stderr[-4000:], encoding="utf-8")
        finally:
            with _git_lock:
                subprocess.run(["git", "worktree", "remove", "--force", str(repo)], cwd=ROOT,
                               check=False, capture_output=True)
            shutil.rmtree(work, ignore_errors=True)
        if done.returncode == 0:
            return "ok"
        kind = _classify(rundir)
        if kind == "auth":
            stop.set()
            raise Abort("Claude Code is not logged in (claude-mcp: auth); log in, then rerun")
        if kind != "usage-limit":
            return f"failed (exit {done.returncode})"
        _say(f"{config} {scenario.id} rep{rep}: usage limit reached, waiting "
             f"{USAGE_WAIT_S // 60} min ({attempt + 1}/{USAGE_MAX_WAITS})")
        stop.wait(USAGE_WAIT_S)
    return "failed (usage limit)"


def agent(config: str, scan_run: str, selection: str, reps: int, jobs: int,
          validate: bool) -> int:
    if not os.environ.get("CLAUDE_BIN") and not shutil.which("claude"):
        raise sc.ScenarioError("set CLAUDE_BIN to the Claude Code CLI")
    scan = RESULTS / "scans" / scan_run
    scenarios = sc.select(selection)
    missing = [s.id for s in scenarios if not (scan / s.id / "clusters.json").is_file()]
    if missing:
        raise sc.ScenarioError(f"not fetched from scan run {scan_run}: {', '.join(missing)}")
    tasks = [(s, rep) for rep in range(1, reps + 1) for s in scenarios]
    stop, failures = threading.Event(), []

    def work(task):
        scenario, rep = task
        try:
            status = run_one(config, scan, scenario, rep, validate and rep == 1, stop)
        except Abort as exc:
            status = f"aborted: {exc}"
        except (sc.ScenarioError, subprocess.TimeoutExpired, OSError) as exc:
            status = f"failed: {type(exc).__name__}: {str(exc)[:200]}"
        _say(f"{config} {scenario.id} rep{rep}: {status}")
        if status not in ("ok", "skip"):
            failures.append((scenario.id, rep, status))

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        list(pool.map(work, tasks))
    _say(f"{config}: {len(tasks) - len(failures)}/{len(tasks)} runs done")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--run", required=True, help="Benchmark scan workflow run id")
    f.add_argument("--baseline-run", help="earlier scan run holding S00's DAST")
    a = sub.add_parser("agent")
    a.add_argument("--config", required=True, choices=sorted(CONFIGS))
    a.add_argument("--scan", required=True, help="fetched scan run id")
    a.add_argument("--select", default="dev")
    a.add_argument("--reps", type=int, default=1)
    a.add_argument("--jobs", type=int, default=3)
    a.add_argument("--validate", action="store_true", help="validate patches (first rep)")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "fetch":
            _say(f"fetched into {fetch(args.run, args.baseline_run)}")
            return 0
        return agent(args.config, args.scan, args.select, args.reps, args.jobs, args.validate)
    except (sc.ScenarioError, subprocess.CalledProcessError) as exc:
        _say(f"run.py: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
