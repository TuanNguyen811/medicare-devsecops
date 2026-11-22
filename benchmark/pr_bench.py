"""The benchmark as real pull requests: every scenario is a PR into main, scanned by the real
pipeline (pr-security.yml), reviewed once by secagent (LLM mode claude-mcp, handed over with
security/handoff/local_review.py), and judged by the real quality gate.

    uv run --project agent --with pyyaml==6.0.2 python benchmark/pr_bench.py open    --tag T
    uv run --project agent --with pyyaml==6.0.2 python benchmark/pr_bench.py review  --tag T
    uv run --project agent --with pyyaml==6.0.2 python benchmark/pr_bench.py collect --tag T
    uv run --project agent --with pyyaml==6.0.2 python benchmark/evaluate.py \\
        --scan pr-T --select test --configs C2 --out benchmark/results/summary/pr-T

open     one branch and PR "[Bench] <ID> ..." per scenario (default: test, dev and S00), the
         scenario's patch applied on main. State: results/pr/<T>/prs.json.
review   waits for each PR's ai-security-agent job, then runs local_review.py
         --benchmark-view (the agent sees exactly the tree the benchmark gave it: no answer
         key, no results), at most --jobs at a time. Output and trace go to
         results/runs/pr-<T>/C2/<ID>/rep1/, as for run.py.
collect  waits for each PR's run to finish, downloads its SARIF into results/scans/pr-<T>/<ID>/,
         computes what evaluate.py needs (run.py _scan_views, on the PR's own commits) and
         records the real pipeline's decision in pipeline.json.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import run as runner
import scenario as sc

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RESULTS = HERE / "results"
AGENT_JOB = "ai-security-agent"
POLL_S = 45


def _say(text: str) -> None:
    print(f"pr-bench: {text}", flush=True)


def sh(*cmd: str, cwd: Path = ROOT, check: bool = True) -> str:
    done = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                          check=False)
    if check and done.returncode != 0:
        raise sc.ScenarioError(f"{' '.join(cmd[:4])}: {done.stderr.strip()[:300]}")
    return done.stdout


def gh_json(path: str):
    return json.loads(sh("gh", "api", path))


def repo_name() -> str:
    return sh("gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner").strip()


def state_file(tag: str) -> Path:
    return RESULTS / "pr" / tag / "prs.json"


def load_state(tag: str) -> dict:
    path = state_file(tag)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def save_state(tag: str, state: dict) -> None:
    path = state_file(tag)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


# --- open ---------------------------------------------------------------------------------------


def open_prs(tag: str, spec: str) -> None:
    state, repo = load_state(tag), repo_name()
    sh("git", "fetch", "--quiet", "origin", "main")
    base = sh("git", "rev-parse", "origin/main").strip()
    work = Path(tempfile.mkdtemp(prefix="pr-bench-"))
    tree = work / "tree"
    try:
        sh("git", "worktree", "add", "--quiet", "--detach", str(tree), base)
        for s in sc.select(spec):
            if s.id in state:
                continue
            branch = f"bench/{tag}/{s.dir.name.lower()}"
            sh("git", "checkout", "--quiet", "--detach", base, cwd=tree)
            text = s.patch_text()
            if text:
                subprocess.run(["git", "apply", "--index", "--whitespace=nowarn", "-"], cwd=tree,
                               input=text.encode("utf-8"), check=True)
            sh("git", "commit", "--quiet", "--allow-empty", "-m", s.commit_message, "-m",
               "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>", cwd=tree)
            head = sh("git", "rev-parse", "HEAD", cwd=tree).strip()
            sh("git", "push", "--quiet", "--force", "origin", f"HEAD:refs/heads/{branch}", cwd=tree)
            body = (f"PR của bộ benchmark (kịch bản {s.id}, loại {s.kind}, tập {s.split}). "
                    "Pipeline và AI Security Agent chạy như với một PR thật; kết quả được chấm "
                    "theo đáp án của kịch bản. **Không merge.**\n\n"
                    "🤖 Generated with [Claude Code](https://claude.com/claude-code)")
            url = sh("gh", "pr", "create", "--repo", repo, "--base", "main", "--head", branch,
                     "--title", f"[Bench] {s.id} · {s.commit_message}", "--body", body).strip()
            state[s.id] = {"pr": int(url.rsplit("/", 1)[1]), "branch": branch, "base": base,
                           "head": head, "kind": s.kind, "split": s.split}
            save_state(tag, state)
            _say(f"{s.id} → {url}")
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(tree)], cwd=ROOT,
                       capture_output=True, check=False)
        subprocess.run(["git", "worktree", "prune"], cwd=ROOT, capture_output=True, check=False)
        shutil.rmtree(work, ignore_errors=True)


# --- review -------------------------------------------------------------------------------------


def _runs_by_pr(repo: str) -> dict[int, dict]:
    """The latest PR Security run of every open PR."""
    runs = gh_json(f"repos/{repo}/actions/workflows/pr-security.yml/runs"
                   "?event=pull_request&per_page=100")["workflow_runs"]
    latest: dict[int, dict] = {}
    for r in runs:
        for p in r.get("pull_requests") or []:
            if p["number"] not in latest or r["id"] > latest[p["number"]]["id"]:
                latest[p["number"]] = r
    return latest


def _agent_job(repo: str, run_id: int) -> dict | None:
    jobs = gh_json(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")["jobs"]
    return next((j for j in jobs if j["name"] == AGENT_JOB), None)


def _rundir(tag: str, sid: str) -> Path:
    return RESULTS / "runs" / f"pr-{tag}" / "C2" / sid / "rep1"


def _scrub_tree(folder: Path) -> None:
    """Committed results must not carry this machine's paths."""
    for path in folder.rglob("*"):
        if path.is_file() and path.suffix in (".json", ".jsonl", ".md", ".txt", ".sarif"):
            text = path.read_bytes().decode("utf-8", errors="replace")
            path.write_bytes(runner._scrub(text).encode("utf-8"))


def review(tag: str, jobs: int) -> None:
    state, repo = load_state(tag), repo_name()
    version = runner.agent_version()
    todo = [sid for sid in state
            if not (_rundir(tag, sid) / "timing.json").is_file()
            or json.loads((_rundir(tag, sid) / "timing.json").read_text())["exit"] != 0]
    active: dict[str, tuple[subprocess.Popen, float, int, object]] = {}
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    env.pop("VIRTUAL_ENV", None)
    while todo or active:
        for sid, (proc, started, run_id, log) in list(active.items()):
            if proc.poll() is None:
                continue
            log.close()
            rundir = _rundir(tag, sid)
            _scrub_tree(rundir)
            (rundir / "timing.json").write_text(json.dumps({
                "config": "C2", "scenario": sid, "rep": 1, "scan": f"pr-{tag}",
                "pr": state[sid]["pr"], "run": run_id, **version,
                "exit": proc.returncode, "wall_s": round(time.monotonic() - started, 2),
                "attempt": 0, "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
            }, indent=2), encoding="utf-8")
            _say(f"{sid}: secagent exit {proc.returncode}")
            del active[sid]
        if todo and len(active) < jobs:
            latest = _runs_by_pr(repo)
            for sid in list(todo):
                if len(active) >= jobs:
                    break
                run = latest.get(state[sid]["pr"])
                if run is None or run["head_sha"] != state[sid]["head"]:
                    continue
                job = _agent_job(repo, run["id"])
                if job is None or job["status"] not in ("in_progress", "completed"):
                    continue
                if job["status"] == "completed" and job["conclusion"] == "skipped":
                    _say(f"{sid}: {AGENT_JOB} skipped; not reviewed")
                    todo.remove(sid)
                    continue
                rundir = _rundir(tag, sid)
                if rundir.exists():
                    shutil.rmtree(rundir)
                rundir.mkdir(parents=True)
                log = (rundir / "review.log").open("w", encoding="utf-8")
                proc = subprocess.Popen(
                    [sys.executable, str(ROOT / "security" / "handoff" / "local_review.py"),
                     "--pr", str(state[sid]["pr"]), "--benchmark-view", "--timeout", "10800",
                     "--save", str(rundir)],
                    cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
                active[sid] = (proc, time.monotonic(), run["id"], log)
                todo.remove(sid)
                _say(f"{sid}: reviewing PR #{state[sid]['pr']} (run {run['id']})")
        time.sleep(POLL_S if not active else 10)


# --- collect ------------------------------------------------------------------------------------


def collect(tag: str) -> None:
    state, repo = load_state(tag), repo_name()
    gate = runner._load_gate()
    out = RESULTS / "scans" / f"pr-{tag}"
    for sid, info in sorted(state.items(), key=lambda kv: (kv[0] != sc.BASELINE, kv[0])):
        dest = out / sid
        if (dest / "pipeline.json").is_file():
            continue
        while True:
            run = _runs_by_pr(repo).get(info["pr"])
            if run and run["head_sha"] == info["head"] and run["status"] == "completed":
                break
            _say(f"{sid}: waiting for PR #{info['pr']}'s run")
            time.sleep(POLL_S)
        raw = Path(tempfile.mkdtemp(prefix="pr-bench-raw-"))
        try:
            sh("gh", "run", "download", str(run["id"]), "--repo", repo, "--dir", str(raw),
               "--pattern", "sarif-*")
            dest.mkdir(parents=True, exist_ok=True)
            for path in raw.rglob("*.sarif"):
                shutil.copy(path, dest / path.name)
            sh("gh", "run", "download", str(run["id"]), "--repo", repo, "--dir",
               str(raw / "agent"), "--name", "agent-report", check=False)
            exit_file = raw / "agent" / "agent-exit"
            agent_exit = int(exit_file.read_text().strip()) if exit_file.is_file() else None
        finally:
            shutil.rmtree(raw, ignore_errors=True)
        missing = [t for t in runner.SCANNERS if not (dest / f"{t}.sarif").is_file()]
        if missing or not (dest / "zap.sarif").is_file():
            raise sc.ScenarioError(f"{sid}: missing SARIF {missing or ['zap']}")
        (dest / "scenario.json").write_text(json.dumps(
            {"id": sid, "base": info["base"], "head": info["head"], "pr": info["pr"],
             "run": run["id"]}, indent=2), encoding="utf-8")
        runner._scan_views(dest, gate)
        jobs = gh_json(f"repos/{repo}/actions/runs/{run['id']}/jobs?per_page=100")["jobs"]
        conclusions = {j["name"]: j["conclusion"] for j in jobs}
        (dest / "pipeline.json").write_text(json.dumps({
            "pr": info["pr"], "run": run["id"], "agent_exit": agent_exit,
            "quality_gate": conclusions.get("quality-gate"),
            "blocked": conclusions.get("quality-gate") != "success",
            "jobs": conclusions}, indent=2), encoding="utf-8")
        _say(f"{sid}: collected (gate {conclusions.get('quality-gate')})")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=("open", "review", "collect"))
    ap.add_argument("--tag", required=True, help="names the branches and the result folders")
    ap.add_argument("--select", default="test,dev,S00",
                    help="scenarios for open (scenario.select syntax per comma-part)")
    ap.add_argument("--jobs", type=int, default=3, help="local reviews at a time")
    args = ap.parse_args(argv)
    try:
        if args.command == "open":
            ids: list[str] = []
            for part in args.select.split(","):
                ids += [s.id for s in sc.select(part.strip()) if s.id not in ids]
            open_prs(args.tag, ",".join(ids))
        elif args.command == "review":
            review(args.tag, args.jobs)
        else:
            collect(args.tag)
    except sc.ScenarioError as exc:
        _say(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
