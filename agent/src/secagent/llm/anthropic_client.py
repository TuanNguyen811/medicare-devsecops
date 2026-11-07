"""Claude (Anthropic Messages API) client.

Translates the agent's OpenAI-format history to Messages API content blocks and back.
Current Claude models (Opus 5.5, Sonnet 5.5): thinking is always on and depth is set with
output_config.effort; sampling parameters are rejected; forced tool_choice (any/tool) is
rejected, so "required" becomes auto plus the caller's instruction; thinking blocks are echoed
back unchanged, and the history must stay append-only (no tool-set changes mid-conversation).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import anthropic

from secagent.llm.base import LLMError, LLMResponse, ToolCall, describe, with_retries

if TYPE_CHECKING:
    import httpx2

    from secagent.config import Settings

RETRYABLE = (anthropic.APIConnectionError, anthropic.RateLimitError,
             anthropic.InternalServerError)  # InternalServerError covers 529 OverloadedError
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 16_000


def _object(arguments: str | None) -> dict:
    try:
        value = json.loads(arguments or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def to_anthropic(messages: list[dict], tools: list[dict], tool_choice: str,
                 settings: Settings) -> dict:
    """Request keyword arguments (all but model) for client.beta.messages.create."""
    system_parts: list[str] = []
    converted: list[dict] = []

    def push(role: str, blocks: list[dict]) -> None:
        if converted and converted[-1]["role"] == role:
            converted[-1]["content"].extend(blocks)
        else:
            converted.append({"role": role, "content": list(blocks)})

    for message in messages:
        role = message.get("role")
        if role == "system" and not converted:
            system_parts.append(message.get("content") or "")
        elif role == "assistant":
            if message.get("anthropic_content") is not None:
                blocks = list(message["anthropic_content"])
            else:
                blocks = [{"type": "text", "text": message["content"]}] if message.get(
                    "content") else []
                blocks += [{"type": "tool_use", "id": call["id"],
                            "name": call["function"]["name"],
                            "input": _object(call["function"].get("arguments"))}
                           for call in message.get("tool_calls") or []]
            push("assistant", blocks or [{"type": "text", "text": "…"}])
        elif role == "tool":
            content = message.get("content") or ""
            block = {"type": "tool_result", "tool_use_id": message["tool_call_id"],
                     "content": content}
            if content.startswith("ERROR"):
                block["is_error"] = True
            push("user", [block])
        else:  # user, or a system message after the first turn
            push("user", [{"type": "text", "text": message.get("content") or ""}])

    request: dict = {"max_tokens": MAX_TOKENS, "messages": converted,
                     "cache_control": {"type": "ephemeral"}}
    if system_parts:
        request["system"] = "\n\n".join(system_parts)
    if tools:
        request["tools"] = [{"name": t["function"]["name"],
                             "description": t["function"].get("description", ""),
                             "input_schema": t["function"]["parameters"]} for t in tools]
        request["tool_choice"] = {"type": "auto"}  # "required" is not accepted by Claude
    if settings.temperature is not None:
        request["temperature"] = settings.temperature
    if settings.thinking:
        request["thinking"] = {"type": "adaptive"}
        request["output_config"] = {"effort": "high"}
    if settings.base_url is None:  # server-side refusal fallbacks: first-party API only
        request["betas"] = [FALLBACK_BETA]
        request["fallbacks"] = "default"
    return request


class AnthropicClient:
    def __init__(self, settings: Settings, *, http_client: httpx2.Client | None = None,
                 sleep: Callable[[float], object] = time.sleep) -> None:
        self.settings = settings
        self.sleep = sleep
        self._client = anthropic.Anthropic(api_key=settings.api_key, base_url=settings.base_url,
                                           timeout=settings.timeout_s, max_retries=0,
                                           http_client=http_client)

    def complete(self, messages: list[dict], tools: list[dict],
                 tool_choice: str = "auto") -> LLMResponse:
        s = self.settings
        request = to_anthropic(messages, tools, tool_choice, s)
        try:
            response = with_retries(
                lambda: self._client.beta.messages.create(model=s.model, **request),
                attempts=s.attempts, sleep=self.sleep, retryable=RETRYABLE)
        except anthropic.APIError as exc:
            raise LLMError(describe(exc)) from None
        try:
            return self._parse(response)
        except (AttributeError, TypeError, ValueError, KeyError, IndexError) as exc:
            raise LLMError(f"phản hồi không hợp lệ ({type(exc).__name__})") from None

    @staticmethod
    def _parse(response) -> LLMResponse:
        if response.stop_reason == "refusal":
            category = getattr(response.stop_details, "category", None) or "không rõ"
            raise LLMError(f"refusal ({category})")
        content = list(response.content)
        text = "\n".join(b.text for b in content if b.type == "text") or None
        thinking = "\n".join(b.thinking for b in content if b.type == "thinking" and b.thinking)
        usage = response.usage
        tokens_in = (usage.input_tokens + (usage.cache_creation_input_tokens or 0)
                     + (usage.cache_read_input_tokens or 0))
        return LLMResponse(
            content=text,
            tool_calls=[ToolCall(b.id, b.name, json.dumps(b.input, ensure_ascii=False))
                        for b in content if b.type == "tool_use"],
            reasoning=thinking or None,
            tokens_in=tokens_in,
            tokens_out=usage.output_tokens,
            provider_blocks=[b.to_dict(mode="json") for b in content],
        )
