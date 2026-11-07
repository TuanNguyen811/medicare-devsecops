"""Provider-neutral LLM interface: one completion call over an OpenAI-format history."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import httpx2

    from secagent.config import Settings

RETRY_DELAYS = (2, 4)


class LLMError(Exception):
    """The LLM call failed for good (after retries, or not retryable). Never carries the key."""


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON text, exactly as the model produced it


@dataclass
class LLMResponse:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    reasoning: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    provider_blocks: list[dict] | None = None  # Claude content blocks, echoed back unchanged

    def assistant_message(self) -> dict:
        message: dict = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            message["tool_calls"] = [
                {"id": c.id, "type": "function",
                 "function": {"name": c.name, "arguments": c.arguments}}
                for c in self.tool_calls
            ]
        if self.provider_blocks is not None:
            message["anthropic_content"] = self.provider_blocks
        elif self.reasoning is not None:
            message["reasoning_content"] = self.reasoning  # DeepSeek wants it back in the turn
        return message


class LLMClient(Protocol):
    def complete(self, messages: list[dict], tools: list[dict],
                 tool_choice: str = "auto") -> LLMResponse: ...


def describe(exc: BaseException) -> str:
    """Error text safe for logs and reports: class name and HTTP status only."""
    status = getattr(exc, "status_code", None)
    return f"{type(exc).__name__}" + (f" (HTTP {status})" if status else "")


def with_retries[T](fn: Callable[[], T], *, attempts: int, sleep: Callable[[float], object],
                 retryable: tuple[type[BaseException], ...]) -> T:
    for attempt in range(attempts):
        try:
            return fn()
        except retryable as exc:
            if attempt == attempts - 1:
                raise LLMError(describe(exc)) from None
            sleep(RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)])
    raise LLMError("no attempt was made")


def make_client(settings: Settings, *, http_client: httpx2.Client | None = None,
                sleep: Callable[[float], object] = time.sleep) -> LLMClient:
    if settings.client == "anthropic":
        from secagent.llm.anthropic_client import AnthropicClient

        return AnthropicClient(settings, http_client=http_client, sleep=sleep)
    from secagent.llm.openai_compat import OpenAIChatClient

    return OpenAIChatClient(settings, http_client=http_client, sleep=sleep)
