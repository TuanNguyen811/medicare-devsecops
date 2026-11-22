import pytest

from secagent.config import PROVIDERS, ConfigError, Settings, cost_usd, step_limit

KEY = {"LLM_API_KEY": "k-123"}


def settings(env=None, **kw) -> Settings:
    return Settings.from_env({**KEY, **(env or {})}, mode="ci", **kw)


def test_settings_from_env():
    s = settings()
    assert (s.provider, s.client, s.base_url, s.model) == (
        "anthropic", "anthropic", None, "claude-opus-5-5")
    assert s.temperature is None and s.reasoning_effort is None and s.thinking is False
    assert settings({"LLM_MODEL": ""}).model == "claude-opus-5-5"
    assert settings(thinking=True).model == "claude-opus-5-5"
    assert settings({"LLM_MODEL": "claude-x"}, thinking=True).model == "claude-x"
    assert settings({"LLM_MODEL": "claude-x"}, model_override="cli-model").model == "cli-model"
    assert settings({"LLM_BASE_URL": "https://proxy.example/v1"}).base_url == \
        "https://proxy.example/v1"
    with pytest.raises(ConfigError):
        Settings.from_env({}, mode="ci")
    with pytest.raises(ConfigError):
        Settings.from_env({"LLM_API_KEY": ""}, mode="ci")
    assert "k-123" not in repr(s)


def test_settings_carry_run_options():
    s = settings(strategy="single-shot", use_requirements=False, use_ast_tools=False,
                 time_budget_s=90)
    assert (s.strategy, s.use_requirements, s.use_ast_tools, s.time_budget_s, s.mode) == (
        "single-shot", False, False, 90, "ci")
    assert (s.timeout_s, s.attempts, s.token_budget, s.batch_size) == (120.0, 3, 400_000, 15)


@pytest.mark.parametrize("provider", ["openai", "gemini", "anthropic"])
def test_provider_presets(provider):
    s = settings({"LLM_PROVIDER": provider})
    thinking = settings({"LLM_PROVIDER": provider}, thinking=True)
    if provider == "openai":
        assert s.client == "openai" and s.base_url == "https://api.openai.com/v1"
        assert s.temperature is None and s.reasoning_effort is None
        assert thinking.reasoning_effort == "high"
    if provider == "gemini":
        assert s.base_url == "https://generativelanguage.googleapis.com/v1beta/openai/"
        assert s.temperature == 0 and thinking.reasoning_effort == "high"
    if provider == "anthropic":
        assert s.client == "anthropic" and s.model == "claude-opus-5-5"
        assert s.temperature is None and s.base_url is None
        assert thinking.thinking and thinking.temperature is None
        assert thinking.reasoning_effort is None
        with pytest.raises(ConfigError):
            settings({"LLM_PROVIDER": provider, "LLM_TEMPERATURE": "0"})


def test_claude_mcp_needs_no_key_and_never_runs_in_ci():
    env = {"LLM_PROVIDER": "claude-mcp"}
    for mode in ("cli", "benchmark"):
        s = Settings.from_env(env, mode=mode)
        assert (s.client, s.model, s.api_key, s.temperature) == (
            "claude-mcp", "claude-sonnet-5-5", "", None)
    # A key in the environment is never forwarded: Claude Code uses its own login.
    assert Settings.from_env({**env, **KEY}, mode="benchmark").api_key == ""
    assert Settings.from_env(env, mode="benchmark", model_override="m").model == "m"
    with pytest.raises(ConfigError):
        Settings.from_env({**env, **KEY}, mode="ci")
    with pytest.raises(ConfigError):
        Settings.from_env(env, mode="benchmark", thinking=True)


def test_unknown_provider_and_bad_temperature_rejected():
    with pytest.raises(ConfigError):
        settings({"LLM_PROVIDER": "skynet"})
    with pytest.raises(ConfigError):
        settings({"LLM_TEMPERATURE": "hot"})
    gemini = {"LLM_PROVIDER": "gemini"}
    assert settings({**gemini, "LLM_TEMPERATURE": "none"}).temperature is None
    assert settings({**gemini, "LLM_TEMPERATURE": "0.2"}).temperature == 0.2
    assert settings({"LLM_PROVIDER": "Gemini"}).provider == "gemini"
    assert set(PROVIDERS) == {"anthropic", "openai", "gemini", "claude-mcp"}


@pytest.mark.parametrize("n,limit", [(0, 10), (5, 25), (15, 55), (17, 60), (100, 60)])
def test_step_limit(n, limit):
    assert step_limit(n) == limit


def test_cost_usd():
    assert cost_usd(1_000_000, 1_000_000, settings()) == 24.0  # anthropic by default
    assert cost_usd(1_000_000, 1_000_000, settings({"LLM_PROVIDER": "openai"})) == 0.0
    assert cost_usd(1_000_000, 1_000_000, settings({"LLM_PROVIDER": "gemini"})) == 0.0
    priced = settings({"LLM_PROVIDER": "anthropic", "LLM_PRICE_IN_PER_M": "3",
                       "LLM_PRICE_OUT_PER_M": "15"})
    assert cost_usd(1_000_000, 1_000_000, priced) == pytest.approx(18.0)
    with pytest.raises(ConfigError):
        settings({"LLM_PRICE_IN_PER_M": "free"})
