"""Command line: `secagent` (review, roadmap Contract 2).

Exit code 0: the run completed (unjudged clusters are NEEDS_REVIEW). Exit code 2: the agent
failed (missing key, bad arguments, no successful LLM call, unexpected error); the quality
gate then falls back to traditional mode.
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from secagent.config import ConfigError, Settings, cost_usd
from secagent.llm.base import LLMClient, make_client
from secagent.models import Meta, Report
from secagent.phases.check import build_entries, ensure_coverage
from secagent.phases.review import ReviewContext, run_review
from secagent.report.markdown import render_failure
from secagent.stages import prepare, write_outputs
from secagent.trace import Trace

LLMFactory = Callable[[Settings], LLMClient]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secagent", description="AI Security Agent cho Pull Request")
    p.add_argument("--mode", choices=("ci", "cli", "benchmark"), default="cli")
    p.add_argument("--repo", default=".")
    p.add_argument("--base", required=True, help="commit gốc (base của PR)")
    p.add_argument("--head", required=True, help="commit của PR")
    p.add_argument("--sarif-dir", default="sarif")
    p.add_argument("--requirements", default="docs/security-requirements.md")
    p.add_argument("--out", default="out")
    p.add_argument("--strategy", choices=("agent", "single-shot"), default="agent")
    p.add_argument("--no-requirements", action="store_true")
    p.add_argument("--no-ast-tools", action="store_true")
    p.add_argument("--thinking", action="store_true")
    p.add_argument("--model")
    p.add_argument("--time-budget-s", type=float)
    return p


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _printer(mode: str) -> Callable[[str, dict], None]:
    if mode != "cli":
        return lambda kind, data: None

    def show(kind: str, data: dict) -> None:
        if kind == "llm":
            calls = ", ".join(data["tool_calls"]) or "(trả lời bằng văn bản)"
            _say(f"[bước {data['step']}/{data['limit']}] → {calls}")
            if data["content"].strip():
                _say(f"    💬 {data['content'].strip()[:300]}")
        elif kind == "tool":
            mark = "✓" if data["ok"] else "✗"
            _say(f"    {mark} {data['name']}({data['arguments'][:120]})")

    return show


def _run(args: argparse.Namespace, settings: Settings, llm_factory: LLMFactory, trace: Trace,
         out: Path) -> int:
    started, started_at = time.monotonic(), datetime.now(UTC).isoformat(timespec="seconds")
    repo = Path(args.repo).resolve()
    prep = prepare(repo, args.base, args.head, Path(args.sarif_dir), args.requirements,
                   settings.use_requirements, trace)
    fs, diff, clusters = prep.fs, prep.diff, prep.clusters
    trace.event("start", mode=settings.mode, provider=settings.provider, model=settings.model,
                strategy=settings.strategy, clusters=len(clusters), findings=len(prep.findings),
                relevant_findings=len(prep.relevant), sarif_errors=prep.sarif_errors,
                changed_files=sorted(diff.changed))
    ctx = ReviewContext(fs=fs, diff=diff, clusters=clusters, requirements=prep.requirements,
                        settings=settings)
    llm = llm_factory(settings)
    if hasattr(llm, "transcript_dir"):  # claude-mcp: keep each session's conversation
        llm.transcript_dir = out / "claude-mcp"
    outcome = run_review(ctx, llm, trace, on_event=_printer(settings.mode))
    if outcome.llm_calls == 0 and outcome.error:
        (out / "report.md").write_text(render_failure(outcome.error), encoding="utf-8")
        _say(f"secagent: không gọi được LLM ({outcome.error})")
        return 2
    uncovered = ensure_coverage(outcome, clusters, settings)
    entries = build_entries(clusters, outcome, fs, trace)
    cost = (outcome.cost_usd if outcome.cost_usd is not None
            else cost_usd(outcome.tokens_in, outcome.tokens_out, settings))
    raw = Report(meta=Meta(
        model=outcome.model or settings.model, provider=settings.provider,
        strategy=settings.strategy, started_at=started_at,
        duration_s=round(time.monotonic() - started, 2), llm_calls=outcome.llm_calls,
        tool_calls=outcome.tool_calls, tokens_in=outcome.tokens_in,
        tokens_out=outcome.tokens_out,
        cost_usd=round(cost, 6),
        step_limit=outcome.step_limit, limit_hit=outcome.limit_hit,
        uncovered_before_check=uncovered, error=outcome.error), findings=entries)
    report = write_outputs(raw, prep, out, args.head)
    entries = report.findings
    counts = Counter(e.verdict for e in entries)
    trace.event("done", verdicts=dict(counts), duration_s=report.meta.duration_s,
                cost_usd=report.meta.cost_usd)
    _say(f"secagent: {counts['TP']} TP · {counts['NEEDS_REVIEW']} NEEDS_REVIEW · "
         f"{counts['FP']} FP · {sum(e.source == 'agent' for e in entries)} phát hiện mới · "
         f"{outcome.llm_calls} lần gọi LLM · {report.meta.duration_s:.1f} s")
    if settings.mode == "cli":
        for e in entries:
            _say(f"  {e.verdict:<12} {e.severity:<8} {e.title}  ({e.file}:{e.line})")
    return 0


def main(argv: list[str] | None = None, *, llm_factory: LLMFactory | None = None,
         env: Mapping[str, str] | None = None) -> int:
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        settings = Settings.from_env(
            os.environ if env is None else env, mode=args.mode, strategy=args.strategy,
            thinking=args.thinking, use_requirements=not args.no_requirements,
            use_ast_tools=not args.no_ast_tools, model_override=args.model,
            time_budget_s=args.time_budget_s)
    except ConfigError as exc:
        _say(f"secagent: {exc}")
        return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    trace = Trace(out / "trace.jsonl")
    try:
        return _run(args, settings, llm_factory or make_client, trace, out)
    except Exception as exc:  # fail safe: the gate falls back to traditional mode
        trace.event("crash", error=type(exc).__name__)
        (out / "report.md").write_text(render_failure(type(exc).__name__), encoding="utf-8")
        _say(f"secagent: lỗi bất ngờ {type(exc).__name__}")
        return 2
    finally:
        trace.close()


def run() -> None:
    sys.exit(main())


# --- secagent-validate ----------------------------------------------------------------------

DEFAULT_TEST_CMD = "uv run --project app --locked pytest -q -x"


def _tool_versions(repo: Path) -> dict[str, str]:
    path = repo / "security" / "tool-versions.env"
    if not path.is_file():
        return {}
    pairs = (line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines()
             if "=" in line and not line.lstrip().startswith("#"))
    return {k.strip(): v.strip() for k, v in pairs}


def default_scan_cmd(repo: Path) -> list[str] | None:
    versions = _tool_versions(repo)
    if "SEMGREP_VERSION" not in versions:
        return None
    pin = (["--exclude-newer", versions["TOOLS_EXCLUDE_NEWER"]]
           if "TOOLS_EXCLUDE_NEWER" in versions else [])
    return ["uvx", *pin, "--from", f"semgrep=={versions['SEMGREP_VERSION']}", "semgrep", "scan",
            "--metrics", "off", "--quiet", "--error", "--disable-nosem",
            "--config", "security/semgrep/medicare.yml"]


def main_validate(argv: list[str] | None = None, *, runner=None) -> int:
    """Validate the TP patches of out/report.json; never fails the pipeline (exit 0)."""
    from secagent.phases.validate_patch import run_command, validate_report

    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="secagent-validate",
                                description="Kiểm chứng bản vá Agent đề xuất (không cần secret)")
    p.add_argument("--out", default="out")
    p.add_argument("--repo", default=".")
    p.add_argument("--head")
    p.add_argument("--max-patches", type=int, default=2)
    p.add_argument("--timeout-s", type=float, default=240)
    p.add_argument("--test-cmd", default=DEFAULT_TEST_CMD)
    p.add_argument("--scan-cmd", default=None,
                   help='mặc định: Semgrep với rule của dự án; "none" để tắt')
    args = p.parse_args(argv)
    out, repo = Path(args.out), Path(args.repo).resolve()
    if not (out / "report.json").is_file():
        _say("secagent-validate: không có gì để kiểm chứng (thiếu report.json)")
        return 0
    if args.scan_cmd is None:
        scan_cmd = default_scan_cmd(repo)
    elif args.scan_cmd.lower() == "none":
        scan_cmd = None
    else:
        scan_cmd = shlex.split(args.scan_cmd)
    try:
        report = validate_report(repo, out, max_patches=args.max_patches,
                                 test_cmd=shlex.split(args.test_cmd), scan_cmd=scan_cmd,
                                 runner=runner or run_command, timeout_s=args.timeout_s,
                                 head_sha=args.head)
    except Exception as exc:  # validation is advisory: the gate never reads `validated`
        _say(f"secagent-validate: bỏ qua do lỗi {type(exc).__name__}")
        return 0
    checked = [e for e in report.findings if e.fix is not None and e.fix.validated is not None]
    passed = sum(1 for e in checked if e.fix.validated)
    _say(f"secagent-validate: {passed}/{len(checked)} bản vá qua kiểm chứng")
    return 0


def run_validate() -> None:
    sys.exit(main_validate())
