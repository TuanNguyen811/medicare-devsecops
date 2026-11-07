import json

import httpx2 as httpx
import pytest

from secagent.config import Settings
from secagent.llm.anthropic_client import AnthropicClient
from secagent.llm.base import LLMError, ToolCall, make_client
from secagent.llm.openai_compat import OpenAIChatClient

KEY = "sk-test-" + "1234567890"
TOOLS = [{"type": "function", "function": {
    "name": "read_file", "description": "Read a file",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}},
                   "required": ["path"]}}}]


def settings(env=None, **kw) -> Settings:
    return Settings.from_env({"LLM_API_KEY": KEY, **(env or {})}, mode="ci", **kw)


def completion(message: dict, tin: int = 11, tout: int = 7) -> dict:
    return {"id": "c1", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
            "usage": {"prompt_tokens": tin, "completion_tokens": tout,
                      "total_tokens": tin + tout}}


class Server:
    """httpx transport replaying (status, json body) pairs; records request bodies."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        status, body = item
        return httpx.Response(status, json=body)


def client(server: Server, s: Settings | None = None, sleeps: list | None = None):
    sleep = sleeps.append if sleeps is not None else (lambda _: None)
    return OpenAIChatClient(s or settings(), sleep=sleep,
                            http_client=httpx.Client(transport=httpx.MockTransport(server)))


def test_complete_parses_tool_calls_and_usage():
    call = {"id": "call_1", "type": "function",
            "function": {"name": "read_file", "arguments": '{"path": "a.py"}'}}
    server = Server((200, completion({"role": "assistant", "content": None,
                                      "tool_calls": [call]})))
    resp = client(server).complete([{"role": "user", "content": "hi"}], TOOLS, "auto")
    assert resp.tool_calls == [ToolCall("call_1", "read_file", '{"path": "a.py"}')]
    assert (resp.content, resp.tokens_in, resp.tokens_out, resp.reasoning) == (None, 11, 7, None)
    body = server.requests[0]
    assert body["model"] == "deepseek-chat" and body["temperature"] == 0
    assert body["tools"] == TOOLS and body["tool_choice"] == "auto"
    assert resp.assistant_message() == {"role": "assistant", "content": None,
                                        "tool_calls": [call]}


def test_optional_params_omitted():
    server = Server((200, completion({"role": "assistant", "content": "ok"})),
                    (200, completion({"role": "assistant", "content": "ok"})))
    history = [{"role": "user", "content": "hi"},
               {"role": "assistant", "content": "x", "anthropic_content": [{"type": "text"}]}]
    client(server, settings({"LLM_PROVIDER": "openai"})).complete(history, [], "auto")
    body = server.requests[0]
    assert "temperature" not in body and "tools" not in body and "tool_choice" not in body
    assert "reasoning_effort" not in body and "anthropic_content" not in body["messages"][1]
    client(server, settings({"LLM_PROVIDER": "openai"}, thinking=True)).complete(history, TOOLS)
    assert server.requests[1]["reasoning_effort"] == "high"


def test_retries_then_succeeds():
    error = (500, {"error": {"message": "boom"}})
    server = Server(error, error, (200, completion({"role": "assistant", "content": "done"})))
    sleeps: list = []
    resp = client(server, sleeps=sleeps).complete([{"role": "user", "content": "hi"}], TOOLS)
    assert resp.content == "done" and resp.tool_calls == [] and sleeps == [2, 4]


def test_connection_error_is_retried():
    server = Server(httpx.ConnectError("down"),
                    (200, completion({"role": "assistant", "content": "ok"})))
    assert client(server).complete([{"role": "user", "content": "x"}], TOOLS).content == "ok"


def test_gives_up_after_three_attempts():
    error = (503, {"error": {"message": "busy"}})
    server = Server(error, error, error)
    sleeps: list = []
    with pytest.raises(LLMError):
        client(server, sleeps=sleeps).complete([{"role": "user", "content": "hi"}], TOOLS)
    assert len(server.requests) == 3 and sleeps == [2, 4]


def test_auth_error_not_retried():
    server = Server((401, {"error": {"message": f"Incorrect API key provided: {KEY}"}}))
    with pytest.raises(LLMError) as info:
        client(server).complete([{"role": "user", "content": "hi"}], TOOLS)
    assert len(server.requests) == 1
    assert KEY not in str(info.value) and "401" in str(info.value)


def test_reasoning_content_round_trip():
    server = Server((200, completion({"role": "assistant", "content": "x",
                                      "reasoning_content": "suy nghĩ…"})))
    resp = client(server, settings(thinking=True)).complete([{"role": "user", "content": "q"}],
                                                            TOOLS)
    assert resp.reasoning == "suy nghĩ…"
    assert resp.assistant_message()["reasoning_content"] == "suy nghĩ…"
    assert server.requests[0]["model"] == "deepseek-reasoner"


def test_make_client_picks_by_provider():
    assert isinstance(make_client(settings()), OpenAIChatClient)
    assert isinstance(make_client(settings({"LLM_PROVIDER": "gemini"})), OpenAIChatClient)
    assert isinstance(make_client(settings({"LLM_PROVIDER": "anthropic"})), AnthropicClient)
