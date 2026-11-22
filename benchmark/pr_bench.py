"""The benchmark as real pull requests: every scenario is a PR into main, scanned by the real
pipeline (pr-security.yml), reviewed once by secagent (LLM mode claude-mcp, handed over with
security/handoff/local_review.py), and judged by the real quality gate.

    uv run --project agent --with pyyaml==6.0.2 python benchmark/pr_bench.py run --tag T
    (or step by step: open, review, collect)
    uv run --project agent --with pyyaml==6.0.2 python benchmark/evaluate.py \\
        --scan pr-T --select test --configs C2 --out benchmark/results/summary/pr-T

run      open, review and collect --batch PRs at a time (few agent jobs wait at once, which keeps
         the pipeline token's API budget and the review queue small), then the next batch.
open     one branch and PR "[Bench] <ID> ..." per scenario (default: test and dev, S00 with them), the
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


def gh_retry(path: str, tries: int = 5):
    """gh api with retries: one failed poll must not stop a long run."""
    for attempt in range(tries):
        try:
            return gh_json(path)
        except (sc.ScenarioError, json.JSONDecodeError) as exc:
            if attempt == tries - 1:
                raise
            _say(f"gh api failed ({str(exc)[:120]}); retrying")
            time.sleep(30 * (attempt + 1))
    raise AssertionError("unreachable")


def pr_run(repo: str, info: dict) -> dict | None:
    """The latest PR Security run of this PR's head commit."""
    runs = gh_retry(f"repos/{repo}/actions/runs?event=pull_request&head_sha={info['head']}"
                    "&per_page=20")["workflow_runs"]
    mine = [r for r in runs if r.get("path", "").endswith("pr-security.yml")
            and any(p["number"] == info["pr"] for p in r.get("pull_requests") or [])]
    return max(mine, key=lambda r: r["id"]) if mine else None


def _jobs(repo: str, run_id: int) -> list[dict]:
    return gh_retry(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")["jobs"]


def _agent_job(repo: str, run_id: int) -> dict | None:
    return next((j for j in _jobs(repo, run_id) if j["name"] == AGENT_JOB), None)


def _rundir(tag: str, sid: str) -> Path:
    return RESULTS / "runs" / f"pr-{tag}" / "C2" / sid / "rep1"


def _scrub(text: str) -> str:
    """Committed results must not carry this machine's paths (home and repo)."""
    for path in (ROOT, Path.home()):
        text = text.replace(str(path), "~" if path == Path.home() else "<repo>")
        text = text.replace(path.as_posix(), "~" if path == Path.home() else "<repo>")
    return text


def _scrub_tree(folder: Path) -> None:
    for path in folder.rglob("*"):
        if path.is_file() and path.suffix in (".json", ".jsonl", ".md", ".txt", ".sarif",
                                              ".log"):
            text = path.read_bytes().decode("utf-8", errors="replace")
            path.write_bytes(_scrub(text).encode("utf-8"))


def _done(tag: str, sid: str) -> bool:
    timing = _rundir(tag, sid) / "timing.json"
    return timing.is_file() and json.loads(timing.read_text(encoding="utf-8"))["exit"] == 0


def review(tag: str, jobs: int, only: list[str] | None = None) -> None:
    """Review every PR of `only` (default: all) once its agent job runs; retry usage limits."""
    state, repo = load_state(tag), repo_name()
    version = runner.agent_version()
    todo = [sid for sid in (only or list(state)) if not _done(tag, sid)]
    waits = dict.fromkeys(todo, 0)
    not_before: dict[str, float] = {}
    active: dict[str, tuple[subprocess.Popen, int, bool, object]] = {}
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    env.pop("VIRTUAL_ENV", None)
    try:
        while todo or active:
            for sid, (proc, run_id, late, log) in list(active.items()):
                if proc.poll() is None:
                    continue
                log.close()
                del active[sid]
                rundir = _rundir(tag, sid)
                _scrub_tree(rundir)
                kind = runner.classify(rundir)
                code = proc.returncode
                if kind == "auth":
                    raise sc.ScenarioError("Claude Code is not logged in")
                if code == 0 and kind:  # stopped midway by the plan's limit: not a result
                    code = 3
                report = rundir / "report.json"
                meta = (json.loads(report.read_text(encoding="utf-8")).get("meta") or {}
                        if report.is_file() else {})
                (rundir / "timing.json").write_text(json.dumps({
                    "config": "C2", "scenario": sid, "rep": 1, "scan": f"pr-{tag}",
                    "pr": state[sid]["pr"], "run": run_id, "base": state[sid]["base"],
                    "head": state[sid]["head"], **version, "exit": code,
                    "wall_s": meta.get("duration_s"), "late": late, "attempt": waits[sid],
                    "finished_at": datetime.now(UTC).isoformat(timespec="seconds"),
                }, indent=2), encoding="utf-8")
                _say(f"{sid}: secagent exit {code}" + (f" ({kind})" if kind else ""))
                if code == 3 and waits[sid] < runner.USAGE_MAX_WAITS:
                    waits[sid] += 1
                    not_before[sid] = time.monotonic() + runner.USAGE_WAIT_S
                    todo.append(sid)
                    _say(f"{sid}: usage limit; retrying in {runner.USAGE_WAIT_S // 60} min")
            for sid in list(todo):
                if len(active) >= jobs:
                    break
                if time.monotonic() < not_before.get(sid, 0):
                    continue
                run = pr_run(repo, state[sid])
                if run is None or run["status"] == "queued":
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
                active[sid] = (proc, run["id"], job["status"] == "completed", log)
                todo.remove(sid)
                _say(f"{sid}: reviewing PR #{state[sid]['pr']} (run {run['id']})")
                time.sleep(15)  # stagger git fetch/worktree add of the reviews
            time.sleep(10 if active else POLL_S)
    finally:
        for proc, _, _, log in active.values():  # never leave orphaned reviews behind
            proc.wait()
            log.close()


# --- collect ------------------------------------------------------------------------------------


def _wait_completed(repo: str, info: dict, sid: str) -> dict:
    while True:
        run = pr_run(repo, info)
        if run and run["status"] == "completed":
            return run
        _say(f"{sid}: waiting for PR #{info['pr']}'s run")
        time.sleep(POLL_S)


def _agent_exit(repo: str, run_id: int) -> int | None:
    raw = Path(tempfile.mkdtemp(prefix="pr-bench-agent-"))
    try:
        sh("gh", "run", "download", str(run_id), "--repo", repo, "--dir", str(raw), "--name",
           "agent-report", check=False)
        exit_file = raw / "agent-exit"
        return int(exit_file.read_text().strip()) if exit_file.is_file() else None
    finally:
        shutil.rmtree(raw, ignore_errors=True)


def collect(tag: str, only: list[str] | None = None) -> list[str]:
    """Scanner views and the real pipeline decision of every finished PR; returns failures."""
    state, repo = load_state(tag), repo_name()
    gate = runner._load_gate()
    out = RESULTS / "scans" / f"pr-{tag}"
    failed = []
    ids = sorted(only or state, key=lambda i: (i != sc.BASELINE, i))
    for sid in ids:
        info, dest = state[sid], out / sid
        if (dest / "pipeline.json").is_file():
            continue
        run = _wait_completed(repo, info, sid)
        agent_exit = _agent_exit(repo, run["id"])
        if agent_exit != 0 and _done(tag, sid):
            # The report came after the job gave up (late review or retry): run the agent job
            # again (its dependants agent-comment and quality-gate re-run with it).
            job = _agent_job(repo, run["id"])
            _say(f"{sid}: report arrived late; re-running {AGENT_JOB}")
            sh("gh", "run", "rerun", str(run["id"]), "--repo", repo, "--job",
               str(job["id"]))
            time.sleep(30)
            run = _wait_completed(repo, info, sid)
            agent_exit = _agent_exit(repo, run["id"])
        raw = Path(tempfile.mkdtemp(prefix="pr-bench-raw-"))
        try:
            sh("gh", "run", "download", str(run["id"]), "--repo", repo, "--dir", str(raw),
               "--pattern", "sarif-*")
            dest.mkdir(parents=True, exist_ok=True)
            for path in raw.rglob("*.sarif"):
                shutil.copy(path, dest / path.name)
        finally:
            shutil.rmtree(raw, ignore_errors=True)
        missing = [t for t in (*runner.SCANNERS, "zap") if not (dest / f"{t}.sarif").is_file()]
        if missing:
            _say(f"{sid}: missing SARIF {missing}; skipped (re-run the PR's workflow)")
            failed.append(sid)
            continue
        (dest / "scenario.json").write_text(json.dumps(
            {"id": sid, "base": info["base"], "head": info["head"], "pr": info["pr"],
             "run": run["id"]}, indent=2), encoding="utf-8")
        runner._scan_views(dest, gate)
        conclusions = {j["name"]: j["conclusion"] for j in _jobs(repo, run["id"])}
        (dest / "pipeline.json").write_text(json.dumps({
            "pr": info["pr"], "run": run["id"], "run_attempt": run.get("run_attempt"),
            "agent_exit": agent_exit, "quality_gate": conclusions.get("quality-gate"),
            "blocked": conclusions.get("quality-gate") != "success",
            "jobs": conclusions}, indent=2), encoding="utf-8")
        _say(f"{sid}: collected (agent exit {agent_exit}, gate "
             f"{conclusions.get('quality-gate')})")
    return failed


# --- run: everything, in batches ----------------------------------------------------------------


def run_all(tag: str, spec: str, batch: int, jobs: int) -> None:
    """Open, review and collect `batch` PRs at a time: few agent jobs wait at once, which keeps
    the pipeline token's API budget (handoff polling) and the review queue small."""
    ids = _ids(spec)
    for start in range(0, len(ids), batch):
        part = ids[start:start + batch]
        _say(f"batch {start // batch + 1}: {', '.join(part)}")
        open_prs(tag, ",".join(part))
        review(tag, jobs, part)
        failed = collect(tag, part)
        if failed:
            _say(f"batch {start // batch + 1}: not collected {failed}")


def _ids(spec: str) -> list[str]:
    ids: list[str] = []
    for part in spec.split(","):
        ids += [s.id for s in sc.select(part.strip()) if s.id not in ids]
    return ids


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=("run", "open", "review", "collect"))
    ap.add_argument("--tag", required=True, help="names the branches and the result folders")
    ap.add_argument("--select", default="test,dev",
                    help="scenarios, comma-separated (IDs or test/dev; S00 comes with them)")
    ap.add_argument("--batch", type=int, default=6, help="run: PRs opened at a time")
    ap.add_argument("--jobs", type=int, default=3, help="local reviews at a time")
    args = ap.parse_args(argv)
    try:
        if args.command == "run":
            run_all(args.tag, args.select, args.batch, args.jobs)
        elif args.command == "open":
            open_prs(args.tag, ",".join(_ids(args.select)))
        elif args.command == "review":
            review(args.tag, args.jobs)
        else:
            failed = collect(args.tag)
            if failed:
                _say(f"not collected: {failed}")
                return 1
    except sc.ScenarioError as exc:
        _say(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
