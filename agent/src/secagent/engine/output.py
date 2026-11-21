"""The Claude Code engine's output: read its execution file, extract its verdicts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from secagent.models import NewFindingArgs, VerdictArgs

TOOL_INPUT_LIMIT = 300
# Bounds for the brace-balanced fallback, so hostile model text cannot stall the gate.
SCAN_LIMIT = 200_000
MAX_CANDIDATES = 10
MAX_DEPTH = 64
JSON_BLOCK = re.compile(r"```json[ \t]*\r?\n(.*?)```", re.DOTALL)


class EngineOutput(BaseModel):
    verdicts: list[VerdictArgs] = Field(default_factory=list)
    new_findings: list[NewFindingArgs] = Field(default_factory=list)


class EngineOutputError(Exception):
    """The engine produced no usable output; the caller falls back to the traditional gate."""


@dataclass
class ExecutionSummary:
    result_text: str | None
    structured: dict | None
    model: str | None
    num_turns: int
    tool_calls: int
    tokens_in: int
    tokens_out: int
    cost_usd: float
    duration_s: float
    is_error: bool
    tool_events: list[dict] = field(default_factory=list)


def _load_messages(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise EngineOutputError(f"cannot read execution file: {exc}") from exc
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        try:
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        except (ValueError, RecursionError) as exc:
            raise EngineOutputError("execution file is not JSON") from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not all(isinstance(m, dict) for m in data):
        raise EngineOutputError("execution file is not a message list")
    return data


def _int(value) -> int:
    return value if isinstance(value, int) else 0


def _num(value) -> float:
    return float(value) if isinstance(value, int | float) else 0.0


def parse_execution(path: Path) -> ExecutionSummary:
    messages = _load_messages(path)
    results = [m for m in messages if m.get("type") == "result"]
    if not results:
        raise EngineOutputError("execution file has no result message")
    result = results[-1]

    model = None
    tool_events: list[dict] = []
    for message in messages:
        kind = message.get("type")
        if kind == "system" and message.get("subtype") == "init" and not model:
            model = message.get("model") or None
        elif kind == "assistant":
            inner = message.get("message")
            content = inner.get("content") if isinstance(inner, dict) else None
            for block in content if isinstance(content, list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    raw = json.dumps(block.get("input"), ensure_ascii=False)
                    tool_events.append({"name": block.get("name"),
                                        "input": raw[:TOOL_INPUT_LIMIT]})
    if not model:
        usage_by_model = result.get("modelUsage")
        if isinstance(usage_by_model, dict) and usage_by_model:
            model = next(iter(usage_by_model))

    usage = result.get("usage") if isinstance(result.get("usage"), dict) else {}
    text = result.get("result")
    structured = result.get("structured_output")
    return ExecutionSummary(
        result_text=text if isinstance(text, str) else None,
        structured=structured if isinstance(structured, dict) else None,
        model=model,
        num_turns=_int(result.get("num_turns")),
        tool_calls=len(tool_events),
        tokens_in=(_int(usage.get("input_tokens")) + _int(usage.get("cache_read_input_tokens"))
                   + _int(usage.get("cache_creation_input_tokens"))),
        tokens_out=_int(usage.get("output_tokens")),
        cost_usd=_num(result.get("total_cost_usd")),
        duration_s=_num(result.get("duration_ms")) / 1000,
        is_error=bool(result.get("is_error")),
        tool_events=tool_events,
    )


def _balanced_span(text: str, start: int) -> int | None:
    """End index of the brace-balanced span opening at start, or None (strings respected)."""
    depth, in_string, escaped = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
            if depth > MAX_DEPTH:
                return None
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def _balanced_object(text: str) -> str | None:
    """The LAST top-level brace-balanced {...} span near the end of text.

    The last one, not the longest: the answer comes at the end, while an earlier object may be
    quoted from the PR's (attacker-controlled) code. Work is bounded: balanced spans do not
    overlap, so scanning them is linear, and at most MAX_CANDIDATES unbalanced starts are
    retried.
    """
    text = text[-SCAN_LIMIT:]
    last = None
    failures = 0
    start = text.find("{")
    while start != -1 and failures < MAX_CANDIDATES:
        end = _balanced_span(text, start)
        if end is None:
            failures += 1
            start = text.find("{", start + 1)
            continue
        last = text[start:end]
        start = text.find("{", end)
    return last


def extract_engine_output(summary: ExecutionSummary) -> EngineOutput:
    if summary.is_error:
        reason = (summary.result_text or "no detail")[:200]
        raise EngineOutputError(f"engine reported an error: {reason}")
    if summary.structured is not None:
        data = summary.structured
    else:
        text = summary.result_text or ""
        blocks = JSON_BLOCK.findall(text)
        raw = blocks[-1] if blocks else _balanced_object(text)
        if raw is None:
            raise EngineOutputError("no JSON verdicts found in the engine answer")
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise EngineOutputError("engine answer JSON is malformed") from exc
    try:
        return EngineOutput.model_validate(data)
    except ValidationError as exc:
        raise EngineOutputError(
            f"engine output violates the schema: {exc.error_count()} error(s)") from exc
    except RecursionError as exc:
        raise EngineOutputError("engine output is nested too deeply") from exc
