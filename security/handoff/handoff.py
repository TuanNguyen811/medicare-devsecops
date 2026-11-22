"""Hand a secagent report produced on the reviewer's machine over to the PR pipeline.

With LLM_PROVIDER=claude-mcp the LLM is Claude Code logged in on one machine, which never runs
on CI. `security/handoff/local_review.py` runs secagent there on the PR's own scanner results and
posts the report as a PR comment (`pack`). The `ai-security-agent` job waits for that comment
(`wait`) and continues as if it had run the agent itself: agent-comment and the quality gate
are unchanged.

Trust: only a comment written by AGENT_REPORT_AUTHOR (a human login: the reviewer running Claude
Code) for the PR's exact head commit, and never edited, is accepted. Other users' comments are
ignored, and so are edited ones: anyone with write access can edit someone else's comment, which
keeps its author, so an edited handoff proves nothing. When AGENT_REPORT_AUTHOR opens the PR
themselves, nothing stops them from handing in any verdict: this mode is not an independent check
of the reviewer.

    python3 security/handoff/handoff.py pack --dir out --sha <head>      > comment.md
    python3 security/handoff/handoff.py wait --repo o/r --pr 12 --sha <head> \\
        --author <login> --out out [--timeout 900]

Exit codes of `wait`: 0 report written to --out; 2 no valid report (the gate falls back to
traditional mode, as when the agent is unavailable).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import json
import re
import subprocess
import sys
import time
import zlib
from collections.abc import Callable, Iterable
from pathlib import Path

FILES = ("report.json", "report.md", "review.json", "agent.sarif")
MAX_BYTES = 2_000_000  # decompressed payload
MAX_COMMENT = 65_000  # GitHub limits a comment body to 65 536 characters
POLL_S = 15
BLOB = re.compile(r"```\n([A-Za-z0-9+/=\n]+)\n```")


class HandoffError(Exception):
    pass


def marker(sha: str) -> str:
    return f"<!-- secagent-handoff sha={sha} -->"


def pack(out: Path, sha: str) -> str:
    """The PR comment carrying the report files of `out` for commit `sha`."""
    files = {n: (out / n).read_text(encoding="utf-8") for n in FILES if (out / n).is_file()}
    if "report.json" not in files:
        raise HandoffError(f"no report.json in {out}")
    body = _body(files, sha)
    if len(body) > MAX_COMMENT and "agent.sarif" in files:
        # agent.sarif only feeds the Security tab: drop it rather than lose the report.
        body = _body({n: v for n, v in files.items() if n != "agent.sarif"}, sha)
    if len(body) > MAX_COMMENT:
        raise HandoffError(f"report too large for a PR comment ({len(body)} characters)")
    return body


def _body(files: dict[str, str], sha: str) -> str:
    blob = base64.b64encode(gzip.compress(json.dumps(files).encode("utf-8"))).decode("ascii")
    lines = "\n".join(blob[i:i + 76] for i in range(0, len(blob), 76))
    return (f"{marker(sha)}\n"
            "<details><summary>secagent: kết quả chạy trên máy người review (claude-mcp), "
            f"chuyển cho pipeline của commit <code>{sha[:7]}</code></summary>\n\n"
            f"```\n{lines}\n```\n</details>\n")


def unpack(body: str, sha: str) -> dict[str, str]:
    """The report files carried by a handoff comment for commit `sha`; raises if invalid."""
    if not body.startswith(marker(sha)):
        raise HandoffError("not a handoff for this commit")
    match = BLOB.search(body)
    if not match:
        raise HandoffError("no payload")
    try:
        raw = base64.b64decode(match.group(1).replace("\n", ""), validate=True)
        inflater = zlib.decompressobj(wbits=31)  # gzip
        data = inflater.decompress(raw, MAX_BYTES + 1)
        if len(data) > MAX_BYTES or inflater.unconsumed_tail:
            raise HandoffError("payload too large")
        files = json.loads(data.decode("utf-8"))
        if not inflater.eof:
            raise HandoffError("truncated payload")
    except (binascii.Error, zlib.error, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise HandoffError(f"unreadable payload ({type(exc).__name__})") from None
    if not isinstance(files, dict) or "report.json" not in files:
        raise HandoffError("payload has no report.json")
    unknown = set(files) - set(FILES)
    if unknown or not all(isinstance(v, str) for v in files.values()):
        raise HandoffError(f"unexpected payload entries {sorted(unknown)}")
    try:
        report = json.loads(files["report.json"])
    except (ValueError, RecursionError):
        raise HandoffError("report.json is not JSON") from None
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise HandoffError("report.json has no findings list")
    return files


def wait(fetch: Callable[[], Iterable[dict]], sha: str, author: str, out: Path,
         timeout_s: float, sleep: Callable[[float], object] = time.sleep,
         clock: Callable[[], float] = time.monotonic) -> int:
    """Poll the PR comments until the trusted author's unedited handoff for `sha` arrives."""
    if not author:
        print("handoff: AGENT_REPORT_AUTHOR is not set; no report can be accepted")
        return 2
    deadline = clock() + timeout_s
    while True:
        handoffs = [c for c in fetch()
                    if c.get("login") == author and c.get("edited") is False
                    and str(c.get("body", "")).startswith(marker(sha))]
        if handoffs:
            latest = max(handoffs, key=lambda c: c.get("id", 0))
            try:
                files = unpack(latest["body"], sha)
            except HandoffError as exc:
                print(f"handoff: comment {latest.get('id')} rejected: {exc}")
                return 2
            out.mkdir(parents=True, exist_ok=True)
            for name, text in files.items():
                (out / name).write_text(text, encoding="utf-8")
            print(f"handoff: report from {author} accepted (comment {latest.get('id')})")
            return 0
        if clock() >= deadline:
            print(f"handoff: no report from {author} for {sha[:7]} within {timeout_s:.0f} s")
            return 2
        sleep(POLL_S)


COMMENTS_QUERY = """
query($owner: String!, $name: String!, $pr: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $pr) {
      comments(last: 100) { nodes { databaseId body lastEditedAt author { login } } }
    }
  }
}"""


def parse_comments(data: dict) -> list[dict]:
    """GraphQL answer -> [{id, login, body, edited}]; a deleted (ghost) author has no login."""
    nodes = data["data"]["repository"]["pullRequest"]["comments"]["nodes"]
    return [{"id": n.get("databaseId") or 0, "login": (n.get("author") or {}).get("login"),
             "body": n.get("body") or "", "edited": n.get("lastEditedAt") is not None}
            for n in nodes]


def _gh_comments(repo: str, pr: int) -> list[dict]:
    """The PR's latest 100 comments (gh CLI with the job's GH_TOKEN)."""
    owner, name = repo.split("/", 1)
    done = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={COMMENTS_QUERY}", "-f", f"owner={owner}",
         "-f", f"name={name}", "-F", f"pr={pr}"],
        capture_output=True, text=True, encoding="utf-8", check=False)
    try:
        if done.returncode != 0:
            raise ValueError(done.stderr.strip()[:200])
        return parse_comments(json.loads(done.stdout))
    except (ValueError, KeyError, TypeError) as exc:
        print(f"handoff: listing comments failed: {exc}")
        return []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pack")
    p.add_argument("--dir", required=True)
    p.add_argument("--sha", required=True)
    w = sub.add_parser("wait")
    w.add_argument("--repo", required=True)
    w.add_argument("--pr", type=int, required=True)
    w.add_argument("--sha", required=True)
    w.add_argument("--author", default="")
    w.add_argument("--out", required=True)
    w.add_argument("--timeout", type=float, default=900)
    args = ap.parse_args(argv)
    if args.cmd == "pack":
        sys.stdout.write(pack(Path(args.dir), args.sha))
        return 0
    return wait(lambda: _gh_comments(args.repo, args.pr), args.sha, args.author,
                Path(args.out), args.timeout)


if __name__ == "__main__":
    sys.exit(main())
