import json

import httpx2 as httpx
import pytest

from secagent.config import Settings
from secagent.llm.anthropic_client import FALLBACK_BETA, AnthropicClient, to_anthropic
from secagent.llm.base import LLMError, ToolCall

KEY = "sk-ant-test-" + "abcdef123456"
TOOLS = [{"type": "function", "function": {
    "name": "read_file", "description": "Read a file",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}},
                   "required": ["path"]}}}]
ANTHROPIC_TOOLS = [{"name": "read_file", "description": "Read a file",
                    "input_schema": TOOLS[0]["function"]["parameters"]}]


def settings(env=None, **kw) -> Settings:
    return Settings.from_env({"LLM_API_KEY": KEY, "LLM_PROVIDER": "anthropic", **(env or {})},
                             mode="ci", **kw)


def tool_call(call_id: str, path: str) -> dict:
    return {"id": call_id, "type": "function",
            "function": {"name": "read_file", "arguments": json.dumps({"path": path})}}


def message(content: list, stop: str = "tool_use", tin: int = 20, tout: int = 5, **extra) -> dict:
    usage = {"input_tokens": tin, "output_tokens": tout}
    usage.update({k: v for k, v in extra.items() if k.endswith("_tokens")})
    body = {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
            "content": content, "stop_reason": stop, "stop_sequence": None, "usage": usage}
    body.update({k: v for k, v in extra.items() if not k.endswith("_tokens")})
    return body


class Server:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[dict] = []
        self.headers: list[httpx.Headers] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        self.headers.append(request.headers)
        status, body = self.responses.pop(0)
        return httpx.Response(status, json=body)


def client(server: Server, s: Settings | None = None, sleeps: list | None = None):
    sleep = sleeps.append if sleeps is not None else (lambda _: None)
    return AnthropicClient(s or settings(), sleep=sleep,
                           http_client=httpx.Client(transport=httpx.MockTransport(server)))


def test_to_anthropic_converts_history():
    history = [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "review"},
        {"role": "assistant", "content": "Đọc 2 file",
         "tool_calls": [tool_call("t1", "a.py"), tool_call("t2", "b.py")]},
        {"role": "tool", "tool_call_id": "t1", "content": "A"},
        {"role": "tool", "tool_call_id": "t2", "content": "ERROR: access denied: b.py"},
        {"role": "user", "content": "Hãy nộp kết luận"},
    ]
    req = to_anthropic(history, TOOLS, "required", settings())
    assert req["system"] == "SYS"
    assert [m["role"] for m in req["messages"]] == ["user", "assistant", "user"]
    assert req["messages"][1]["content"] == [
        {"type": "text", "text": "Đọc 2 file"},
        {"type": "tool_use", "id": "t1", "name": "read_file", "input": {"path": "a.py"}},
        {"type": "tool_use", "id": "t2", "name": "read_file", "input": {"path": "b.py"}},
    ]
    assert req["messages"][2]["content"] == [
        {"type": "tool_result", "tool_use_id": "t1", "content": "A"},
        {"type": "tool_result", "tool_use_id": "t2", "content": "ERROR: access denied: b.py",
         "is_error": True},
        {"type": "text", "text": "Hãy nộp kết luận"},
    ]
    assert req["tools"] == ANTHROPIC_TOOLS
    assert req["tool_choice"] == {"type": "auto"}  # forced tool use is a 400 on current models
    assert req["max_tokens"] == 16000 and req["cache_control"] == {"type": "ephemeral"}
    assert "temperature" not in req and "thinking" not in req and "output_config" not in req
    assert req["fallbacks"] == "default" and req["betas"] == [FALLBACK_BETA]
    assert history[2]["content"] == "Đọc 2 file"  # the caller's history is not mutated


def test_to_anthropic_without_tools_or_default_endpoint():
    req = to_anthropic([{"role": "user", "content": "x"}], [], "auto",
                       settings({"LLM_BASE_URL": "https://proxy.example"}))
    assert "tools" not in req and "tool_choice" not in req
    assert "fallbacks" not in req and "betas" not in req and "system" not in req


def test_anthropic_complete_parses_tool_use_and_usage():
    content = [{"type": "text", "text": "Đọc file"},
               {"type": "tool_use", "id": "toolu_1", "name": "read_file",
                "input": {"path": "a.py"}}]
    server = Server((200, message(content, cache_read_input_tokens=100,
                                  cache_creation_input_tokens=50)))
    resp = client(server).complete([{"role": "user", "content": "hi"}], TOOLS, "auto")
    assert resp.content == "Đọc file"
    assert resp.tool_calls == [ToolCall("toolu_1", "read_file", '{"path": "a.py"}')]
    assert (resp.tokens_in, resp.tokens_out) == (170, 5)
    body = server.requests[0]
    assert body["model"] == "claude-opus-5-5" and body["tool_choice"] == {"type": "auto"}
    assert FALLBACK_BETA in server.headers[0]["anthropic-beta"]
    assert resp.assistant_message()["anthropic_content"] == content


def test_anthropic_thinking_round_trip():
    blocks = [{"type": "thinking", "thinking": "", "signature": "sig-abc"},
              {"type": "tool_use", "id": "toolu_1", "name": "read_file",
               "input": {"path": "a.py"}}]
    server = Server((200, message(blocks)),
                    (200, message([{"type": "text", "text": "xong"}], stop="end_turn")))
    c = client(server, settings(thinking=True))
    first = c.complete([{"role": "user", "content": "hi"}], TOOLS, "auto")
    history = [{"role": "user", "content": "hi"}, first.assistant_message(),
               {"role": "tool", "tool_call_id": "toolu_1", "content": "A"}]
    assert c.complete(history, TOOLS, "required").content == "xong"
    second = server.requests[1]
    assert second["messages"][1]["content"] == blocks  # thinking + signature echoed unchanged
    assert second["thinking"] == {"type": "adaptive"}
    assert second["output_config"] == {"effort": "high"}
    assert "temperature" not in second and second["tool_choice"] == {"type": "auto"}


def test_anthropic_refusal_raises():
    refusal = message([], stop="refusal",
                      stop_details={"type": "refusal", "category": "cyber", "explanation": "x"})
    with pytest.raises(LLMError) as info:
        client(Server((200, refusal))).complete([{"role": "user", "content": "hi"}], TOOLS)
    assert "refusal" in str(info.value) and "cyber" in str(info.value)


def test_anthropic_overloaded_is_retried():
    overloaded = (529, {"type": "error",
                        "error": {"type": "overloaded_error", "message": "Overloaded"}})
    sleeps: list = []
    server = Server(overloaded, (200, message([{"type": "text", "text": "ok"}], stop="end_turn")))
    resp = client(server, sleeps=sleeps).complete([{"role": "user", "content": "x"}], TOOLS)
    assert resp.content == "ok" and sleeps == [2]


def test_anthropic_auth_error_hides_key():
    server = Server((401, {"type": "error", "error": {"type": "authentication_error",
                                                       "message": f"invalid x-api-key {KEY}"}}))
    with pytest.raises(LLMError) as info:
        client(server).complete([{"role": "user", "content": "x"}], TOOLS)
    assert KEY not in str(info.value) and len(server.requests) == 1
