"""Run secagent with Claude Code on this machine for an open PR, and hand the report over.

For LLM_PROVIDER=claude-mcp (repo variable): the PR's `ai-security-agent` job waits for the
report this script posts (see handoff.py). Steps:
  1. find the PR's "PR Security" run and wait until its scanners and ZAP have finished;
  2. download their SARIF (the same files the job would give the agent);
  3. check out the PR's head commit in a temporary worktree;
  4. run secagent with LLM_PROVIDER=claude-mcp on it;
  5. post the report as a PR comment, which the job picks up.

    uv run --project agent python security/handoff/local_review.py --pr 19

Needs: gh logged in as AGENT_REPORT_AUTHOR, Claude Code logged in (CLAUDE_BIN if `claude` is
not on PATH). The report says provider claude-mcp and the model, like any other run.
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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from handoff import pack  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
AGENT_JOB = "ai-security-agent"
POLL_S = 20


def sh(*cmd: str, cwd: Path = ROOT, env: dict | None = None) -> str:
    done = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True,
                          encoding="utf-8", check=False)
    if done.returncode != 0:
        sys.exit(f"local-review: {' '.join(cmd[:3])} failed: {done.stderr.strip()[:300]}")
    return done.stdout


def gh_json(path: str):
    return json.loads(sh("gh", "api", path))


def pick_run(runs: dict, pr: int) -> int | None:
    """The latest PR Security run of this PR (the same head commit may be in several PRs)."""
    mine = [r for r in runs.get("workflow_runs", [])
            if r.get("path", "").endswith("pr-security.yml")
            and any(p.get("number") == pr for p in r.get("pull_requests") or [])]
    return max(mine, key=lambda r: r["id"])["id"] if mine else None


def find_run(repo: str, pr: int, head: str, timeout_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    while True:
        run = pick_run(gh_json(f"repos/{repo}/actions/runs?head_sha={head}&event=pull_request"),
                       pr)
        if run is not None:
            return run
        if time.monotonic() > deadline:
            sys.exit(f"local-review: no PR Security run for {head[:7]}")
        time.sleep(POLL_S)


def wait_for_agent_job(repo: str, run: int, timeout_s: float) -> bool:
    """Wait until every scanner has uploaded its SARIF (the agent job has started).

    False if the agent job already finished: the report can still be posted, and is picked up
    when the workflow is re-run ("Re-run all jobs"; the job only accepts reports for this head).
    """
    deadline = time.monotonic() + timeout_s
    while True:
        jobs = gh_json(f"repos/{repo}/actions/runs/{run}/jobs?per_page=100")["jobs"]
        job = next((j for j in jobs if j["name"] == AGENT_JOB), None)
        if job and job["status"] == "in_progress":
            return True
        if job and job["status"] == "completed":
            if job["conclusion"] == "skipped":
                sys.exit(f"local-review: {AGENT_JOB} was skipped (fork PR or a failed scanner); "
                         "fix that first, a report would not be used")
            print(f"local-review: {AGENT_JOB} already finished ({job['conclusion']}); "
                  "the report will be posted for a re-run of the workflow", flush=True)
            return False
        if time.monotonic() > deadline:
            sys.exit(f"local-review: {AGENT_JOB} did not start in time")
        pending = sorted(j["name"] for j in jobs if j["status"] != "completed")
        print(f"local-review: waiting for scanners ({', '.join(pending)})", flush=True)
        time.sleep(POLL_S)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--pr", type=int, required=True)
    ap.add_argument("--timeout", type=float, default=1800, help="seconds to wait for the run")
    ap.add_argument("--keep", action="store_true", help="keep the temporary directory")
    args = ap.parse_args(argv)

    repo = sh("gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner").strip()
    pr = gh_json(f"repos/{repo}/pulls/{args.pr}")
    base, head = pr["base"]["sha"], pr["head"]["sha"]
    print(f"local-review: {repo}#{args.pr} {base[:7]}..{head[:7]}", flush=True)
    run = find_run(repo, args.pr, head, args.timeout)
    print(f"local-review: run {run}", flush=True)
    in_time = wait_for_agent_job(repo, run, args.timeout)

    work = Path(tempfile.mkdtemp(prefix="secagent-local-"))
    tree = work / "repo"
    try:
        downloads, sarif = work / "artifacts", work / "sarif"
        sh("gh", "run", "download", str(run), "--repo", repo, "--pattern", "sarif-*",
           "--dir", str(downloads))
        sarif.mkdir()
        for f in downloads.rglob("*.sarif"):
            shutil.copy2(f, sarif / f.name)
        print(f"local-review: {len(list(sarif.iterdir()))} SARIF files", flush=True)

        sh("git", "fetch", "--quiet", "origin", base, f"pull/{args.pr}/head")
        sh("git", "worktree", "add", "--quiet", "--detach", str(tree), head)
        out = work / "out"
        env = {**os.environ, "LLM_PROVIDER": "claude-mcp", "PYTHONIOENCODING": "utf-8"}
        env.pop("VIRTUAL_ENV", None)
        done = subprocess.run(
            ["uv", "run", "--project", str(ROOT / "agent"), "secagent", "--mode", "cli",
             "--repo", str(tree), "--base", base, "--head", head, "--sarif-dir", str(sarif),
             "--requirements", "docs/security-requirements.md", "--out", str(out)],
            cwd=ROOT, env=env, check=False)
        if done.returncode != 0:
            print(f"local-review: secagent exited {done.returncode}; nothing posted "
                  "(the job will time out and the gate falls back to traditional mode)")
            return done.returncode
        body = work / "comment.md"
        body.write_text(pack(out, head), encoding="utf-8", newline="")
        sh("gh", "api", f"repos/{repo}/issues/{args.pr}/comments", "-F", f"body=@{body}")
        if in_time:
            print(f"local-review: report posted to {repo}#{args.pr}; {AGENT_JOB} picks it up",
                  flush=True)
        else:
            print(f"local-review: report posted to {repo}#{args.pr}; re-run all jobs of run "
                  f"{run} (gh run rerun {run}) for the gate to use it", flush=True)
        return 0
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(tree)], cwd=ROOT,
                       capture_output=True, check=False)
        subprocess.run(["git", "worktree", "prune"], cwd=ROOT, capture_output=True, check=False)
        if args.keep:
            print(f"local-review: kept {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
