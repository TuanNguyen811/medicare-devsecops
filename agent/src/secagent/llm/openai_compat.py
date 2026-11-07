"""Chat Completions client for DeepSeek, OpenAI, Gemini and any OpenAI-compatible endpoint."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import openai

from secagent.llm.base import LLMError, LLMResponse, ToolCall, describe, with_retries

if TYPE_CHECKING:
    import httpx2

    from secagent.config import Settings

RETRYABLE = (openai.APIConnectionError, openai.RateLimitError, openai.InternalServerError)


class OpenAIChatClient:
    def __init__(self, settings: Settings, *, http_client: httpx2.Client | None = None,
                 sleep: Callable[[float], object] = time.sleep) -> None:
        self.settings = settings
        self.sleep = sleep
        self._client = openai.OpenAI(api_key=settings.api_key, base_url=settings.base_url,
                                     timeout=settings.timeout_s, max_retries=0,
                                     http_client=http_client)

    def complete(self, messages: list[dict], tools: list[dict],
                 tool_choice: str = "auto") -> LLMResponse:
        s = self.settings
        kwargs: dict = {
            "model": s.model,
            "messages": [{k: v for k, v in m.items() if k != "anthropic_content"}
                         for m in messages],
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice
        if s.temperature is not None:
            kwargs["temperature"] = s.temperature
        if s.reasoning_effort is not None:
            kwargs["reasoning_effort"] = s.reasoning_effort
        try:
            response = with_retries(lambda: self._client.chat.completions.create(**kwargs),
                                    attempts=s.attempts, sleep=self.sleep, retryable=RETRYABLE)
        except openai.APIError as exc:
            raise LLMError(describe(exc)) from None
        try:
            return self._parse(response)
        except (AttributeError, TypeError, ValueError, KeyError, IndexError) as exc:
            raise LLMError(f"phản hồi không hợp lệ ({type(exc).__name__})") from None

    @staticmethod
    def _parse(response) -> LLMResponse:
        if not response.choices:
            raise LLMError("phản hồi rỗng (không có choices)")
        message = response.choices[0].message
        calls = [ToolCall(c.id or f"call_{index}", c.function.name or "",
                          c.function.arguments or "{}")
                 for index, c in enumerate(message.tool_calls or [])
                 if getattr(c, "function", None)]
        reasoning = getattr(message, "reasoning_content", None) or (
            (message.model_extra or {}).get("reasoning_content"))
        usage = response.usage
        return LLMResponse(
            content=message.content, tool_calls=calls, reasoning=reasoning,
            tokens_in=usage.prompt_tokens if usage else 0,
            tokens_out=usage.completion_tokens if usage else 0,
        )
