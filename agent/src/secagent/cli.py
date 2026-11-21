"""Command line: `secagent` (review, roadmap Contract 2).

Exit code 0: the run completed (unjudged clusters are NEEDS_REVIEW). Exit code 2: the agent
failed (missing key, bad arguments, no successful LLM call, unexpected error); the quality
gate then falls back to traditional mode.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shlex
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
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
    outcome = run_review(ctx, llm_factory(settings), trace, on_event=_printer(settings.mode))
    if outcome.llm_calls == 0 and outcome.error:
        (out / "report.md").write_text(render_failure(outcome.error), encoding="utf-8")
        _say(f"secagent: không gọi được LLM ({outcome.error})")
        return 2
    uncovered = ensure_coverage(outcome, clusters, settings)
    entries = build_entries(clusters, outcome, fs, trace)
    raw = Report(meta=Meta(
        model=settings.model, strategy=settings.strategy, started_at=started_at,
        duration_s=round(time.monotonic() - started, 2), llm_calls=outcome.llm_calls,
        tool_calls=outcome.tool_calls, tokens_in=outcome.tokens_in,
        tokens_out=outcome.tokens_out,
        cost_usd=round(cost_usd(outcome.tokens_in, outcome.tokens_out, settings), 6),
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


# --- secagent-prepare -----------------------------------------------------------------------


def main_prepare(argv: list[str] | None = None) -> int:
    """Write out/context/ for the Claude Code engine. Exit 0: done. Exit 2: unexpected error."""
    from secagent.engine.task import build_task, findings_payload, mask_worktree

    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="secagent-prepare",
                                description="Dựng ngữ cảnh cho engine claude-code")
    p.add_argument("--repo", default=".")
    p.add_argument("--base", required=True, help="commit gốc (base của PR)")
    p.add_argument("--head", required=True, help="commit của PR")
    p.add_argument("--sarif-dir", default="sarif")
    p.add_argument("--requirements", default="docs/security-requirements.md")
    p.add_argument("--out", default="out")
    p.add_argument("--no-requirements", action="store_true")
    p.add_argument("--mask-worktree", action="store_true",
                   help="che các dòng Gitleaks báo ngay trong cây làm việc")
    args = p.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    trace = Trace(out / "trace.jsonl")
    try:
        prep = prepare(Path(args.repo).resolve(), args.base, args.head, Path(args.sarif_dir),
                       args.requirements, not args.no_requirements, trace)
        ctx = out / "context"
        ctx.mkdir(parents=True, exist_ok=True)
        files = {
            "findings.json": json.dumps(findings_payload(prep.clusters, prep.diff), indent=2,
                                        ensure_ascii=False),
            "diff.patch": prep.diff.text(max_lines=100000),
            "task.md": build_task(prep),
        }
        if prep.requirements:
            files["requirements.md"] = prep.requirements
        for name, text in files.items():
            (ctx / name).write_text(text, encoding="utf-8", newline="")
        masked = mask_worktree(prep) if args.mask_worktree else 0
        trace.event("prepare", clusters=len(prep.clusters), findings=len(prep.findings),
                    sarif_errors=prep.sarif_errors, masked_lines=masked,
                    changed_files=sorted(prep.diff.changed))
        _say(f"secagent-prepare: {len(prep.clusters)} cụm, {len(prep.diff.changed)} file đổi, "
             f"{masked} dòng bị che")
        return 0
    except Exception as exc:  # fail safe: the gate falls back to traditional mode
        trace.event("crash", error=type(exc).__name__)
        _say(f"secagent-prepare: lỗi bất ngờ {type(exc).__name__}")
        return 2
    finally:
        trace.close()


def run_prepare() -> None:
    sys.exit(main_prepare())


# --- secagent-finalize ----------------------------------------------------------------------


def _fail_finalize(out: Path, trace: Trace | None, kind: str, reason: str, **data) -> int:
    """Exit 2 for secagent-finalize: best-effort trace and failure report, never a traceback."""
    if trace is not None:
        with contextlib.suppress(Exception):  # nothing left to report to; the exit code speaks
            trace.event(kind, error=reason, **data)
    with contextlib.suppress(OSError):
        (out / "report.md").write_text(render_failure(reason), encoding="utf-8", newline="")
    _say(f"secagent-finalize: {reason}")
    return 2


def _outcome_from_engine(engine, summary, clusters, trace: Trace):
    """ReviewOutcome from the engine's answer: known clusters only, the most severe verdict."""
    from secagent.phases.check import VERDICT_ORDER
    from secagent.phases.review import ReviewOutcome

    known = {c.id for c in clusters}
    verdicts: dict = {}
    for v in engine.verdicts:
        if v.cluster_id not in known:
            trace.event("unknown_cluster", cluster_id=v.cluster_id)
            continue
        current = verdicts.get(v.cluster_id)
        if current is None or VERDICT_ORDER[v.verdict] < VERDICT_ORDER[current.verdict]:
            verdicts[v.cluster_id] = v
    return ReviewOutcome(verdicts=verdicts, new_findings=list(engine.new_findings),
                         llm_calls=summary.num_turns, tool_calls=summary.tool_calls,
                         tokens_in=summary.tokens_in, tokens_out=summary.tokens_out)


def _finalize(args: argparse.Namespace, trace: Trace, out: Path) -> int:
    from secagent.context.redact import redact_value
    from secagent.engine.output import (
        EngineOutput,
        EngineOutputError,
        extract_engine_output,
        parse_execution,
    )

    prep = prepare(Path(args.repo).resolve(), args.base, args.head, Path(args.sarif_dir),
                   args.requirements, not args.no_requirements, trace)
    try:
        summary = parse_execution(Path(args.execution_file))
        engine = extract_engine_output(summary)
    except EngineOutputError as exc:
        return _fail_finalize(out, trace, "engine_failed", str(exc))
    for event in summary.tool_events:
        trace.event("engine_tool", name=event["name"], input=event["input"])
    engine = EngineOutput.model_validate(redact_value(engine.model_dump(mode="json")))
    (out / "verdicts.json").write_text(engine.model_dump_json(indent=2), encoding="utf-8",
                                       newline="")
    model = summary.model or args.model or "claude-code"
    trace.event("start", engine="claude-code", model=model, clusters=len(prep.clusters),
                findings=len(prep.findings), relevant_findings=len(prep.relevant),
                sarif_errors=prep.sarif_errors, changed_files=sorted(prep.diff.changed))
    outcome = _outcome_from_engine(engine, summary, prep.clusters, trace)
    uncovered = sum(1 for c in prep.clusters if c.id not in outcome.verdicts)
    entries = build_entries(prep.clusters, outcome, prep.fs, trace)
    started_at = datetime.now(UTC) - timedelta(seconds=summary.duration_s)
    raw = Report(meta=Meta(
        model=model, strategy="claude-code", started_at=started_at.isoformat(timespec="seconds"),
        duration_s=round(summary.duration_s, 2), llm_calls=outcome.llm_calls,
        tool_calls=outcome.tool_calls, tokens_in=outcome.tokens_in, tokens_out=outcome.tokens_out,
        cost_usd=round(summary.cost_usd, 6), step_limit=0, limit_hit=False,
        uncovered_before_check=uncovered, error=None), findings=entries)
    report = write_outputs(raw, prep, out, args.head)
    counts = Counter(e.verdict for e in report.findings)
    trace.event("done", verdicts=dict(counts), duration_s=report.meta.duration_s,
                cost_usd=report.meta.cost_usd)
    _say(f"secagent-finalize: {counts['TP']} TP · {counts['NEEDS_REVIEW']} NEEDS_REVIEW · "
         f"{counts['FP']} FP · {sum(e.source == 'agent' for e in report.findings)} phát hiện mới "
         f"· {report.meta.llm_calls} lượt · {report.meta.duration_s:.1f} s")
    return 0


def main_finalize(argv: list[str] | None = None) -> int:
    """Turn the Claude Code execution file into the classic outputs (exit 0, else exit 2)."""
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="secagent-finalize",
                                description="Hậu kiểm và sinh báo cáo cho engine claude-code")
    p.add_argument("--repo", default=".")
    p.add_argument("--base", required=True, help="commit gốc (base của PR)")
    p.add_argument("--head", required=True, help="commit của PR")
    p.add_argument("--sarif-dir", default="sarif")
    p.add_argument("--requirements", default="docs/security-requirements.md")
    p.add_argument("--out", default="out")
    p.add_argument("--execution-file", required=True, help="execution file của claude-code-action")
    p.add_argument("--engine", choices=("claude-code",), default="claude-code")
    p.add_argument("--model", help="model dự phòng khi execution file không ghi model")
    p.add_argument("--no-requirements", action="store_true")
    args = p.parse_args(argv)
    out = Path(args.out)
    trace: Trace | None = None
    try:
        out.mkdir(parents=True, exist_ok=True)
        trace = Trace(out / "trace.jsonl")
        return _finalize(args, trace, out)
    except Exception as exc:  # fail safe: the gate falls back to traditional mode
        return _fail_finalize(out, trace, "crash", type(exc).__name__)
    finally:
        if trace is not None:
            trace.close()


def run_finalize() -> None:
    sys.exit(main_finalize())
