"""Benchmark scenarios: build a scenario's repository state, list what CI must scan.

    python benchmark/scenario.py materialize <ID> <dest>      # prints {"base": sha, "head": sha}
    python benchmark/scenario.py matrix --select all|S01,S07  # GitHub Actions matrices
    python benchmark/scenario.py list

A scenario lives in benchmark/scenarios/<ID>-<slug>/:
  scenario.yaml     id, title, split (dev|test), kind (vuln|decoy|robustness|baseline),
                    commit_message
  patch.diff        the Pull Request, applied with `git apply` on BASE_COMMIT (absent = no change)
  ground_truth.yaml the expected vulnerabilities (read by evaluate.py, never by the agent)

materialize is deterministic: the same scenario gives the same commit SHAs on any machine
(fixed author, committer and dates; patches go to git as bytes; no hooks), so SARIF from GitHub
Actions and the local agent run refer to the same commits. The base commit is BASE_COMMIT made
neutral: whatever documents the experiment (design documents describe the planted bugs, the
baseline scan report labels the clean tree's findings) is removed or rewritten, and the agent's
own code is not part of the application under review.
Fake secrets are written as @@FAKE:<kind>:<label>@@ in patches and expanded here, so no
secret-looking string is ever committed to this repository.

Needs PyYAML: uv run --no-project --with pyyaml==6.0.2 python benchmark/scenario.py ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SCENARIOS = HERE / "scenarios"
BASE_FILE = HERE / "BASE_COMMIT"
SANITIZED = ("docs/superpowers", "agent", "benchmark", "docs/baseline-scan.md", "docs/pipeline.md",
             "infra/README.md", "deploy/README.md")
# Exact edits of the base tree; a missing `old` text is an error, so nothing slips through when
# the baseline changes.
REWRITES = {
    "docs/security-requirements.md": [
        ("Có ba nhóm sử dụng:", "Có hai nhóm sử dụng:"),
        (("- **Bộ benchmark:** mỗi lỗ hổng logic trong `benchmark/ground_truth.yaml` được gắn với "
         "quy tắc bị vi phạm (`violated_rule: R-xx`).\n"), ""),
    ],
    "app/README.md": [
        (", và **không bao giờ** triển khai các nhánh kịch bản lỗ hổng lên môi trường public.",
         "."),
    ],
    ".gitignore": [
        (("# Benchmark outputs (raw runs; summaries are committed explicitly)\n"
         "benchmark/results/raw/\n\n"), ""),
    ],
    # Comments only: the scanners' behaviour is unchanged.
    "security/tool-versions.env": [
        ("(CI workflows, local scans, benchmark).", "(CI workflows, local scans)."),
        ("so CI, local scans and the benchmark get one tree.", "so CI and local scans get one tree."),
    ],
    "security/dast/run-dast.sh": [
        ("# Used by the PR pipeline, the local deploy (phase 3) and the benchmark (phase 5).",
         "# Used by the PR pipeline and the local deploy."),
    ],
}
NEUTRAL_README = """# MediCare HMS

Hệ thống quản lý bệnh viện (FastAPI, SQLAlchemy, PostgreSQL), kèm pipeline DevSecOps.

- `app/`: ứng dụng; chạy và test: [`app/README.md`](app/README.md)
- `.github/workflows/`: pipeline CI/CD bảo mật
- `security/`: cấu hình các công cụ quét
- `infra/`, `deploy/`: hạ tầng và triển khai
- `docs/security-requirements.md`: quy tắc bảo mật nghiệp vụ R-01…R-19
"""
DAST_TRIGGERS = ("app/", "infra/docker-compose.yml")
ROLES = ("ADMIN", "RECEPTIONIST", "DOCTOR", "NURSE", "PATIENT")
BASELINE = "S00"
KINDS = {"vuln", "decoy", "robustness", "baseline"}
SPLITS = {"dev", "test"}
ID_RE = re.compile(r"^(S|D)\d{2}$")
IDENTITY = {
    "GIT_AUTHOR_NAME": "MediCare Dev", "GIT_AUTHOR_EMAIL": "dev@medicare.example",
    "GIT_COMMITTER_NAME": "MediCare Dev", "GIT_COMMITTER_EMAIL": "dev@medicare.example",
}
BASE_DATE = "2026-11-22T08:00:00+07:00"
HEAD_DATE = "2026-11-22T09:00:00+07:00"
FAKE = re.compile(r"@@FAKE:([a-z0-9-]+):([A-Za-z0-9_-]+)@@")
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


class ScenarioError(Exception):
    pass


@dataclass(frozen=True)
class Scenario:
    id: str
    dir: Path
    title: str
    split: str
    kind: str
    commit_message: str

    @property
    def patch(self) -> Path:
        return self.dir / "patch.diff"

    def patch_text(self) -> str:
        if not self.patch.is_file():
            return ""
        return expand_fakes(self.patch.read_text(encoding="utf-8"), self.id)

    def touched(self) -> list[str]:
        """Files the patch creates, edits or deletes."""
        found = re.findall(r"^(?:\+\+\+ b|--- a)/(\S+)", self.patch_text(), re.MULTILINE)
        return sorted(set(found))

    def touches_app(self) -> bool:
        """Changes what runs (app code, or how compose starts it): needs its own DAST."""
        return any(p.startswith(DAST_TRIGGERS) for p in self.touched())


def _fake(kind: str, seed: bytes) -> str:
    digest = hashlib.sha256(seed).digest() * 4

    def alnum(n: int) -> str:
        return "".join(ALNUM[b % len(ALNUM)] for b in digest[:n])

    if kind == "aws-key-id":
        return "AKIA" + alnum(16)
    if kind == "hex32":
        return digest[:16].hex()
    if kind == "hex64":
        return digest[:32].hex()
    if kind == "sk-live":
        return "sk_live_" + alnum(24).lower()
    raise ScenarioError(f"unknown fake secret kind: {kind}")


def expand_fakes(text: str, scenario_id: str) -> str:
    """Deterministic stand-ins for secrets (same value for the same scenario, kind and label)."""
    return FAKE.sub(lambda m: _fake(m[1], f"{scenario_id}:{m[1]}:{m[2]}".encode()), text)


def load(path: Path) -> Scenario:
    meta = yaml.safe_load((path / "scenario.yaml").read_text(encoding="utf-8")) or {}
    sid = str(meta.get("id", ""))
    if not ID_RE.match(sid) or not path.name.startswith(sid + "-"):
        raise ScenarioError(f"{path.name}: id {sid!r} must be Sxx/Dxx and prefix the folder")
    if meta.get("split") not in SPLITS or meta.get("kind") not in KINDS:
        raise ScenarioError(f"{sid}: split must be {sorted(SPLITS)}, kind {sorted(KINDS)}")
    for key in ("title", "commit_message"):
        if not str(meta.get(key) or "").strip():
            raise ScenarioError(f"{sid}: missing {key}")
    return Scenario(sid, path, meta["title"], meta["split"], meta["kind"],
                    meta["commit_message"].strip())


def all_scenarios() -> list[Scenario]:
    found = [load(p) for p in sorted(SCENARIOS.iterdir()) if p.is_dir()]
    ids = [s.id for s in found]
    if len(ids) != len(set(ids)):
        raise ScenarioError("duplicate scenario id")
    return found


def select(spec: str) -> list[Scenario]:
    scenarios = all_scenarios()
    if spec.strip() in ("", "all"):
        return scenarios
    if spec.strip() in SPLITS:
        return [s for s in scenarios if s.split == spec.strip() or s.id == BASELINE]
    wanted = list(dict.fromkeys(x.strip() for x in spec.split(",") if x.strip()))
    by_id = {s.id: s for s in scenarios}
    unknown = [x for x in wanted if x not in by_id]
    if unknown:
        raise ScenarioError(f"unknown scenario(s): {', '.join(unknown)}")
    return [by_id[x] for x in wanted]


def base_commit() -> str:
    sha = BASE_FILE.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ScenarioError("BASE_COMMIT must hold a full commit SHA")
    return sha


GIT_CONFIG = ("-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
              "-c", "i18n.commitEncoding=UTF-8", "-c", "core.hooksPath=.benchmark-no-hooks")


def _git(args: list[str], cwd: Path, *, date: str | None = None, stdin: str | None = None) -> str:
    """Run git; input goes as UTF-8 bytes (text mode would turn \\n into \\r\\n on Windows)."""
    env = {**os.environ, **IDENTITY}
    if date:
        env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    done = subprocess.run(["git", *GIT_CONFIG, *args], check=False, cwd=cwd, env=env,
                          input=None if stdin is None else stdin.encode("utf-8"),
                          capture_output=True)
    if done.returncode:
        err = done.stderr.decode("utf-8", errors="replace").strip()
        raise ScenarioError(f"git {' '.join(args[:2])}: {err[:500]}")
    return done.stdout.decode("utf-8", errors="replace").strip()


def _commit(dest: Path, message: str, date: str) -> str:
    _git(["commit", "-q", "--allow-empty", "--no-verify", "--cleanup=strip", "-m", message],
         dest, date=date)
    return _git(["rev-parse", "HEAD"], dest)


def _neutralize(dest: Path) -> None:
    present = [p for p in SANITIZED if (dest / p).exists()]
    if present:
        _git(["rm", "-r", "-q", "--", *present], dest)
    for rel, edits in REWRITES.items():
        path = dest / rel
        text = path.read_bytes().decode("utf-8")
        for old, new in edits:
            if old not in text:
                raise ScenarioError(f"{rel}: expected text not found: {old[:60]!r}")
            text = text.replace(old, new)
        path.write_bytes(text.encode("utf-8"))
    (dest / "README.md").write_bytes(NEUTRAL_README.encode("utf-8"))
    _git(["add", "-A", "--", "README.md", *REWRITES], dest)


def materialize(scenario: Scenario, dest: Path, repo: Path) -> dict[str, str]:
    """A detached worktree of `repo` at dest: base commit (sanitized), then the scenario's PR."""
    if dest.exists():
        raise ScenarioError(f"{dest} already exists")
    _git(["worktree", "add", "--detach", "--quiet", str(dest), base_commit()], repo)
    try:
        _neutralize(dest)
        base = _commit(dest, "Phiên bản đang chạy", BASE_DATE)
        text = scenario.patch_text()
        if text:
            _git(["apply", "--index", "--whitespace=nowarn", "-"], dest, stdin=text)
        head = _commit(dest, scenario.commit_message, HEAD_DATE)
    except ScenarioError:
        _git(["worktree", "remove", "--force", str(dest)], repo)
        raise
    return {"id": scenario.id, "base": base, "head": head}


def matrix(scenarios: list[Scenario]) -> dict[str, list]:
    """What CI scans: every scenario with the static tools; ZAP for each scenario that changes
    app/ (the others reuse the S00 baseline's DAST), one job per role."""
    dast_ids = [s.id for s in scenarios if s.touches_app() or s.id == BASELINE]
    return {"scan": [s.id for s in scenarios],
            "dast": [{"id": i, "role": r} for i in dast_ids for r in ROLES]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("materialize")
    m.add_argument("id")
    m.add_argument("dest", type=Path)
    m.add_argument("--repo", type=Path, default=HERE.parent)
    x = sub.add_parser("matrix")
    x.add_argument("--select", default="all")
    sub.add_parser("list")
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        if args.cmd == "materialize":
            (scenario,) = select(args.id)
            print(json.dumps(materialize(scenario, args.dest.resolve(), args.repo.resolve())))
        elif args.cmd == "matrix":
            for key, value in matrix(select(args.select)).items():
                print(f"{key}={json.dumps(value, separators=(',', ':'))}")
        else:
            for s in all_scenarios():
                print(f"{s.id}\t{s.split}\t{s.kind}\tapp={s.touches_app()}\t{s.title}")
    except ScenarioError as exc:
        print(f"scenario.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
