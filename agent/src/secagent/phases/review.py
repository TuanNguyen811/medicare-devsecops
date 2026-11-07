"""Phase 1: the single-pass review session (spec 4.1) driven by function calling.

One session per batch of at most `batch_size` clusters; only the first batch hunts for new
vulnerabilities. A session ends when the model calls `finish`, or at the step limit, where one
extra turn asks it to submit what is missing. The tool list never changes inside a session
(Claude's preserved thinking treats a changed tool set as an edited history), so on that last
turn read tools are refused at execution time instead of being withdrawn.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from secagent.config import Settings, step_limit
from secagent.context.diff import PrDiff
from secagent.context.sarif import Cluster
from secagent.llm.base import LLMClient, LLMError, describe
from secagent.models import SEVERITY_RANK, NewFindingArgs, VerdictArgs
from secagent.tools.fs import RepoFS, ToolError, wrap_untrusted
from secagent.tools.registry import ToolRegistry, ToolSpec, build_read_tools, format_findings
from secagent.trace import Trace

PROMPTS = Path(__file__).resolve().parent.parent / "prompts"
SUBMISSION_TOOLS = ("submit_verdict", "report_finding", "finish")
NUDGE = "Hãy dùng công cụ để nộp kết luận (submit_verdict / report_finding), rồi gọi finish."
FORCE = ("Đã hết số bước cho phép. Từ giờ chỉ được gọi submit_verdict, report_finding và "
         "finish; công cụ đọc không còn chạy. Nộp ngay kết luận cho: {missing}.")
STEP_EXHAUSTED = "ERROR: đã hết số bước, công cụ đọc không còn được dùng; hãy nộp kết luận."
HUNT = ("Also hunt for vulnerabilities the scanners missed in the code changed by this PR, and "
        "report each one with `report_finding`.")
NO_HUNT = ("Hunting for new vulnerabilities happens in another session; only judge the "
           "clusters listed.")
CONTEXT_LINES = 800

EventSink = Callable[[str, dict], None]


def load_prompt(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


def _fill(template: str, values: dict[str, str]) -> str:
    """Single-pass placeholder substitution: text coming from the PR is never re-scanned."""
    return re.sub(r"\{(\w+)\}", lambda m: values.get(m[1], m[0]), template)


def _cluster_key(cluster_id: str) -> int:
    return int(cluster_id[1:]) if cluster_id[1:].isdigit() else 0


@dataclass
class ReviewContext:
    fs: RepoFS
    diff: PrDiff
    clusters: list[Cluster]
    requirements: str | None
    settings: Settings


@dataclass
class ReviewOutcome:
    verdicts: dict[str, VerdictArgs] = field(default_factory=dict)
    new_findings: list[NewFindingArgs] = field(default_factory=list)
    llm_calls: int = 0
    tool_calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    step_limit: int = 0
    limit_hit: bool = False
    error: str | None = None
    sessions: list[Session] = field(default_factory=list)
    unstarted: list[str] = field(default_factory=list)
    started: float = 0.0


def budget_left(outcome: ReviewOutcome, settings: Settings,
                clock: Callable[[], float] = time.monotonic) -> bool:
    return (outcome.tokens_in + outcome.tokens_out < settings.token_budget
            and clock() - outcome.started < settings.time_budget_s)


class FinishArgs(BaseModel):
    summary: str = Field(default="", description="One or two sentences on the review outcome")


def _code_context(ctx: ReviewContext, batch: list[Cluster]) -> str:
    parts, budget = [], CONTEXT_LINES
    targets = [(c.file, max(1, c.line - 15), c.line + 15) for c in batch if c.file]
    targets += [(path, 1, 400) for path in sorted(ctx.diff.changed)]
    for path, start, end in targets:
        if budget <= 0:
            break
        try:
            text = ctx.fs.read_file(path, start, min(end, start + budget - 1))
        except ToolError:
            continue
        parts.append(text)
        budget -= text.count("\n") - 1
    return "\n\n".join(parts) or "(không có)"


def build_user_prompt(ctx: ReviewContext, batch: list[Cluster], hunt: bool,
                      single_shot: bool) -> str:
    changed = "\n".join(f"- {path} (+{len(fd.added)} dòng)"
                        for path, fd in sorted(ctx.diff.files.items())) or "(không có)"
    requirements = (wrap_untrusted("docs/security-requirements.md", ctx.requirements)
                    if ctx.requirements else
                    "(cấu hình này không cung cấp tài liệu quy tắc nghiệp vụ)")
    values = {
        "changed_files": changed,
        "diff": wrap_untrusted("PR diff", ctx.diff.text(max_lines=1500 if single_shot else 600)),
        "findings_table": format_findings(batch),
        "requirements": requirements,
        "hunt": HUNT if hunt else ("" if single_shot else NO_HUNT),
    }
    if single_shot:
        values["code_context"] = _code_context(ctx, batch)
    return _fill(load_prompt("single_shot.md" if single_shot else "review.md"), values)


class Session:
    """The conversation for one batch of clusters."""

    def __init__(self, ctx: ReviewContext, batch: list[Cluster], *, hunt: bool,
                 outcome: ReviewOutcome, llm: LLMClient, trace: Trace, on_event: EventSink,
                 clock: Callable[[], float], single_shot: bool) -> None:
        self.ctx, self.outcome, self.llm, self.trace = ctx, outcome, llm, trace
        self.on_event, self.clock = on_event, clock
        self.batch_ids = {c.id for c in batch}
        self.hunt = hunt
        self.finished = False
        self.forced = False
        self._finish_warned = False
        self.registry = ToolRegistry()
        if not single_shot:
            for spec in build_read_tools(ctx.fs, ctx.diff, batch, ctx.requirements,
                                         ctx.settings.use_ast_tools):
                self.registry.add(spec)
        self.read_tools = set(self.registry.names())
        self.registry.add(ToolSpec("submit_verdict",
                                   "Submit the verdict for one finding cluster of this session.",
                                   VerdictArgs, self._submit))
        if hunt:
            self.registry.add(ToolSpec("report_finding",
                                       "Report a vulnerability that no scanner reported.",
                                       NewFindingArgs, self._report))
        self.registry.add(ToolSpec("finish", "End the review session.", FinishArgs,
                                   self._finish))
        self.messages: list[dict] = [
            {"role": "system", "content": load_prompt("system.md")},
            {"role": "user", "content": build_user_prompt(ctx, batch, hunt, single_shot)},
        ]

    # --- submission tools ---------------------------------------------------------------

    def missing(self) -> list[str]:
        return sorted(self.batch_ids - set(self.outcome.verdicts), key=_cluster_key)

    def _submit(self, args: VerdictArgs) -> str:
        if args.cluster_id not in self.batch_ids:
            known = ", ".join(sorted(self.batch_ids, key=_cluster_key)) or "không có"
            raise ToolError(f"unknown cluster_id {args.cluster_id}; cụm của phiên này: {known}")
        replaced = args.cluster_id in self.outcome.verdicts
        self.outcome.verdicts[args.cluster_id] = args
        self.trace.event("verdict", cluster=args.cluster_id, verdict=args.verdict,
                         replaced=replaced)
        return f"OK: {args.cluster_id} = {args.verdict}" + (" (thay kết luận trước)"
                                                             if replaced else "")

    def _report(self, args: NewFindingArgs) -> str:
        self.outcome.new_findings.append(args)
        self.trace.event("new_finding", title=args.title, severity=args.severity)
        return f"OK: đã ghi phát hiện mới #{len(self.outcome.new_findings)}"

    def _finish(self, args: FinishArgs) -> str:
        missing = self.missing()
        if missing and not self._finish_warned:
            self._finish_warned = True
            return (f"WARNING: chưa có kết luận cho {', '.join(missing)} — nộp bằng "
                    "submit_verdict rồi gọi finish")
        self.finished = True
        self.trace.event("finish", summary=args.summary, missing=missing)
        return "OK: kết thúc phiên review"

    # --- conversation -------------------------------------------------------------------

    def _turn(self, tool_choice: str, limit: int) -> bool:
        """One LLM call plus its tool calls. False when the LLM failed for good."""
        outcome = self.outcome
        try:
            response = self.llm.complete(self.messages, self.registry.schemas(), tool_choice)
        except LLMError as exc:
            outcome.error = str(exc)
            self.trace.event("llm_error", error=str(exc))
            return False
        except Exception as exc:  # any other failure: keep the verdicts already submitted
            outcome.error = describe(exc)
            self.trace.event("llm_error", error=outcome.error)
            return False
        outcome.llm_calls += 1
        outcome.tokens_in += response.tokens_in
        outcome.tokens_out += response.tokens_out
        self.messages.append(response.assistant_message())
        info = {"step": outcome.llm_calls, "limit": limit, "content": response.content or "",
                "tool_calls": [c.name for c in response.tool_calls],
                "tokens_in": response.tokens_in, "tokens_out": response.tokens_out}
        self.trace.event("llm", **info)
        self.on_event("llm", info)
        if not response.tool_calls:
            self.messages.append({"role": "user", "content": NUDGE})
            return True
        for tool_call in response.tool_calls:
            if self.forced and tool_call.name in self.read_tools:
                result = STEP_EXHAUSTED
            else:
                result = self.registry.call(tool_call.name, tool_call.arguments)
            outcome.tool_calls += 1
            self.messages.append({"role": "tool", "tool_call_id": tool_call.id,
                                  "content": result})
            event = {"name": tool_call.name, "arguments": tool_call.arguments[:300],
                     "ok": not result.startswith("ERROR"), "result": result[:300]}
            self.trace.event("tool", **event)
            self.on_event("tool", event)
        return True

    def drive(self, limit: int) -> bool:
        """Run up to `limit` LLM calls; True when the model finished the session."""
        for _ in range(limit):
            if not budget_left(self.outcome, self.ctx.settings, self.clock):
                self.outcome.limit_hit = True
                return False
            if not self._turn("auto", limit):
                return False
            if self.finished:
                return True
        return self.finished

    def force_submit(self) -> None:
        """Step limit reached: one last turn, same tools, read tools refused."""
        self.forced = True
        missing = ", ".join(self.missing()) or "không còn cụm nào"
        self.messages.append({"role": "user", "content": FORCE.format(missing=missing)})
        self._turn("required", 1)

    def ask_missing(self, missing: list[str], limit: int) -> None:
        """Coverage check (phase 2): ask once for the clusters still without a verdict."""
        self._finish_warned = True
        self.finished = False
        self.messages.append({"role": "user", "content": (
            f"Chưa có kết luận cho: {', '.join(missing)}. Dùng submit_verdict cho từng cụm "
            "này, rồi gọi finish.")})
        self.drive(limit)


def run_review(ctx: ReviewContext, llm: LLMClient, trace: Trace,
               on_event: EventSink = lambda kind, data: None,
               clock: Callable[[], float] = time.monotonic) -> ReviewOutcome:
    settings = ctx.settings
    outcome = ReviewOutcome(started=clock())
    size = max(1, settings.batch_size)
    # Most severe first, so a budget that runs out leaves the low-severity clusters unjudged.
    ordered = sorted(ctx.clusters,
                     key=lambda c: (-SEVERITY_RANK.get(c.severity, 0), _cluster_key(c.id)))
    batches = [ordered[i:i + size] for i in range(0, len(ordered), size)] or [[]]
    single_shot = settings.strategy == "single-shot"
    for index, batch in enumerate(batches):
        if outcome.error or not budget_left(outcome, settings, clock):
            outcome.unstarted += [c.id for later in batches[index:] for c in later]
            outcome.limit_hit = outcome.limit_hit or outcome.error is None
            break
        session = Session(ctx, batch, hunt=index == 0, outcome=outcome, llm=llm, trace=trace,
                          on_event=on_event, clock=clock, single_shot=single_shot)
        outcome.sessions.append(session)
        limit = 1 if single_shot else step_limit(len(batch))
        outcome.step_limit += limit
        trace.event("session", batch=[c.id for c in batch], hunt=index == 0, limit=limit)
        finished = session.drive(limit)
        if single_shot or finished or outcome.error:
            continue
        outcome.limit_hit = True
        if budget_left(outcome, settings, clock):
            session.force_submit()
    return outcome
