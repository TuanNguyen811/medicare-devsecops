"""Run settings from environment variables and CLI flags (spec 4.4, plan C Global Constraints).

LLM_PROVIDER picks one of four modes (spec addendum 4.1): `anthropic` (default), `openai` and
`gemini` call the provider's API with LLM_API_KEY; `claude-mcp` uses the Claude Code CLI logged in
on this machine (no key, never in CI). LLM_MODEL / LLM_BASE_URL override the preset.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

ClientKind = Literal["openai", "anthropic", "claude-mcp"]


class ConfigError(Exception):
    """Invalid or missing configuration; the CLI exits with code 2."""


@dataclass(frozen=True)
class ProviderPreset:
    client: ClientKind
    base_url: str | None
    model: str | None
    thinking_model: str | None
    thinking: Literal["reasoning_effort", "anthropic", "none"]
    temperature: float | None
    price_in_per_m: float = 0.0
    price_out_per_m: float = 0.0


PROVIDERS: dict[str, ProviderPreset] = {
    # Claude: thinking is always on (effort is the knob) and sampling parameters are rejected.
    # Prices: Claude Opus 5.5 list price per million tokens.
    "anthropic": ProviderPreset("anthropic", None, "claude-opus-5-5", None, "anthropic", None,
                                4.0, 20.0),
    # GPT-5 family models only accept the default temperature, so none is sent.
    "openai": ProviderPreset("openai", "https://api.openai.com/v1", "gpt-5-mini", None,
                             "reasoning_effort", None),
    "gemini": ProviderPreset("openai", "https://generativelanguage.googleapis.com/v1beta/openai/",
                             "gemini-2.5-flash", None, "reasoning_effort", 0.0),
    # Claude Code on this machine as the LLM, through the MCP bridge (llm/claude_mcp.py). Cost is
    # the API-equivalent figure Claude Code reports, so no price is configured here.
    "claude-mcp": ProviderPreset("claude-mcp", None, "claude-sonnet-5-5", None, "none", None),
}
KEYLESS = frozenset({"claude-mcp"})


@dataclass(frozen=True)
class Settings:
    provider: str
    client: ClientKind
    api_key: str = field(repr=False)
    base_url: str | None = None
    model: str = ""
    thinking: bool = False
    temperature: float | None = 0.0
    reasoning_effort: str | None = None
    strategy: Literal["agent", "single-shot"] = "agent"
    use_requirements: bool = True
    use_ast_tools: bool = True
    mode: Literal["ci", "cli", "benchmark"] = "cli"
    timeout_s: float = 120.0
    attempts: int = 3
    token_budget: int = 400_000
    time_budget_s: float = 360.0
    batch_size: int = 15
    price_in_per_m: float = 0.0
    price_out_per_m: float = 0.0

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str],
        *,
        mode: Literal["ci", "cli", "benchmark"],
        strategy: Literal["agent", "single-shot"] = "agent",
        thinking: bool = False,
        use_requirements: bool = True,
        use_ast_tools: bool = True,
        model_override: str | None = None,
        time_budget_s: float | None = None,
    ) -> Settings:
        def get(name: str) -> str | None:
            value = (env.get(name) or "").strip()
            return value or None

        provider = (get("LLM_PROVIDER") or "anthropic").lower()
        preset = PROVIDERS.get(provider)
        if preset is None:
            raise ConfigError(f"LLM_PROVIDER không hợp lệ: {provider!r}. "
                              f"Chọn một trong: {', '.join(PROVIDERS)}.")
        api_key = get("LLM_API_KEY") or ""
        if provider in KEYLESS:
            on_ci = (env.get("GITHUB_ACTIONS") or "").lower() == "true" or bool(get("CI"))
            if mode == "ci" or on_ci:
                raise ConfigError(f"LLM_PROVIDER={provider} chỉ chạy trên máy, không chạy trên CI.")
            if thinking:
                raise ConfigError(f"LLM_PROVIDER={provider} không hỗ trợ --thinking.")
            api_key = ""  # never forwarded: Claude Code uses its own login
        elif not api_key:
            raise ConfigError("Thiếu LLM_API_KEY: Agent không gọi được LLM.")
        base_url = get("LLM_BASE_URL") or preset.base_url
        model = (model_override or get("LLM_MODEL")
                 or (preset.thinking_model if thinking else None) or preset.model)
        if not model:
            raise ConfigError("Thiếu LLM_MODEL.")

        temperature = preset.temperature
        raw_temperature = get("LLM_TEMPERATURE")
        if raw_temperature is not None:
            temperature = None if raw_temperature.lower() == "none" else _number(
                "LLM_TEMPERATURE", raw_temperature)
        if preset.client == "anthropic" and temperature is not None:
            raise ConfigError("Claude không nhận tham số temperature; bỏ LLM_TEMPERATURE.")
        reasoning_effort = "high" if thinking and preset.thinking == "reasoning_effort" else None

        price_in = get("LLM_PRICE_IN_PER_M")
        price_out = get("LLM_PRICE_OUT_PER_M")
        return cls(
            provider=provider,
            client=preset.client,
            api_key=api_key,
            base_url=base_url,
            model=model,
            thinking=thinking,
            temperature=temperature,
            reasoning_effort=reasoning_effort,
            strategy=strategy,
            use_requirements=use_requirements,
            use_ast_tools=use_ast_tools,
            mode=mode,
            time_budget_s=360.0 if time_budget_s is None else float(time_budget_s),
            price_in_per_m=(preset.price_in_per_m if price_in is None
                            else _number("LLM_PRICE_IN_PER_M", price_in)),
            price_out_per_m=(preset.price_out_per_m if price_out is None
                             else _number("LLM_PRICE_OUT_PER_M", price_out)),
        )


def _number(name: str, raw: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} phải là số: {raw!r}") from exc


def step_limit(n_clusters: int) -> int:
    """Maximum LLM calls of one review session (spec 4.1)."""
    return min(10 + 3 * n_clusters, 60)


def cost_usd(tokens_in: int, tokens_out: int, s: Settings) -> float:
    return (tokens_in * s.price_in_per_m + tokens_out * s.price_out_per_m) / 1_000_000
