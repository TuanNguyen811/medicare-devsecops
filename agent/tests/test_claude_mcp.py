"""LLM mode claude-mcp: relay, MCP bridge, runner command, and the review session driven by it."""

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

from fakes import MINIAPP, miniapp_repo

from secagent.config import Settings
from secagent.context.diff import parse_unified_diff
from secagent.context.sarif import ScanFinding, cluster_findings
from secagent.llm.claude_mcp import (
    BRIDGE,
    ClaudeMcpRunner,
    SessionRun,
    ToolRelay,
    mcp_tools,
    summarize,
)
from secagent.phases.check import ensure_coverage
from secagent.phases.review import STEP_EXHAUSTED, ReviewContext, run_review
from secagent.tools.fs import RepoFS
from secagent.trace import Trace

SERVICE = "app/medicare/demo/service.py"
DIFF = parse_unified_diff(
    f"diff --git a/{SERVICE} b/{SERVICE}\n--- a/{SERVICE}\n+++ b/{SERVICE}\n"
    "@@ -1,2 +1,3 @@\n def load_item(item_id: int) -> dict:\n+    audit(item_id)\n"
    '     return {"id": item_id}\n')
SCHEMA = [{"type": "function", "function": {
    "name": "echo", "description": "Echo", "parameters": {"type": "object", "properties": {}}}}]


def mcp_settings(**kw) -> Settings:
    return Settings.from_env({"LLM_PROVIDER": "claude-mcp"}, mode="benchmark", **kw)


def context(tmp_path, n=1, **kw) -> ReviewContext:
    findings = [ScanFinding("semgrep", f"rule{i}", "HIGH", SERVICE, 1, 1, f"m{i}", (), ())
                for i in range(1, n + 1)]
    req = (MINIAPP / "docs" / "security-requirements.md").read_text(encoding="utf-8")
    return ReviewContext(fs=RepoFS(miniapp_repo(tmp_path)), diff=DIFF,
                         clusters=cluster_findings(findings, DIFF), requirements=req,
                         settings=mcp_settings(**kw))


def verdict(cluster_id: str) -> str:
    return json.dumps({"cluster_id": cluster_id, "verdict": "TP", "confidence": 0.9,
                       "severity": "HIGH", "cwe": "CWE-89", "reasoning": "SQL ghép chuỗi",
                       "evidence": [{"file": SERVICE, "start_line": 1, "end_line": 1}]})


class FakeRunner:
    """Stands in for ClaudeMcpRunner: each session is a script of tool calls."""

    def __init__(self, scripts, subtypes=None):
        self.scripts, self.subtypes, self.sessions = list(scripts), list(subtypes or []), []

    def run_session(self, *, system, prompt, tools, call, max_turns, timeout_s):
        names = [t["function"]["name"] for t in tools]
        results = [call(name, args) for name, args in self.scripts.pop(0)]
        self.sessions.append({"system": system, "prompt": prompt, "tools": names,
                              "max_turns": max_turns, "results": results})
        subtype = self.subtypes.pop(0) if self.subtypes else "success"
        return SessionRun(ok=True, subtype=subtype, turns=3, tokens_in=100, tokens_out=20,
                          cost_usd=0.01, model="claude-sonnet-5-5")


# --- relay and bridge ------------------------------------------------------------------------


def test_mcp_tools_converts_registry_schemas():
    assert mcp_tools(SCHEMA) == [{"name": "echo", "description": "Echo",
                                  "inputSchema": {"type": "object", "properties": {}}}]


def _ask(port, request):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        stream = conn.makefile("rwb")
        stream.write(json.dumps(request).encode() + b"\n")
        stream.flush()
        return stream.readline()


def test_relay_answers_only_with_the_token():
    calls = []
    relay = ToolRelay(mcp_tools(SCHEMA), lambda n, a: calls.append((n, a)) or f"ok {n}")
    try:
        assert _ask(relay.port, {"op": "list", "token": "wrong"}) == b""  # dropped, no answer
        assert json.loads(_ask(relay.port, {"op": "list", "token": relay.token}))["tools"][0][
            "name"] == "echo"
        answer = json.loads(_ask(relay.port, {"op": "call", "name": "echo",
                                              "arguments": {"x": 1}, "token": relay.token}))
        assert answer == {"text": "ok echo", "error": False}
        assert calls == [("echo", '{"x": 1}')]
    finally:
        relay.close()


def test_bridge_speaks_mcp_over_stdio():
    relay = ToolRelay(mcp_tools(SCHEMA), lambda n, a: "ERROR: nope" if n == "bad" else "hi")
    try:
        env = {**os.environ, "SECAGENT_RELAY_PORT": str(relay.port),
               "SECAGENT_RELAY_TOKEN": relay.token}
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "echo", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "bad", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 5, "method": "server/discover"},
        ]
        done = subprocess.run([sys.executable, "-I", str(BRIDGE)], env=env, timeout=30,
                              input="".join(json.dumps(m) + "\n" for m in messages),
                              capture_output=True, text=True, encoding="utf-8")
        replies = {r["id"]: r for r in map(json.loads, done.stdout.splitlines())}
        assert set(replies) == {1, 2, 3, 4, 5}  # nothing for the notification
        assert replies[1]["result"]["protocolVersion"] == "2025-06-18"
        assert replies[2]["result"]["tools"][0]["name"] == "echo"
        assert replies[3]["result"] == {"content": [{"type": "text", "text": "hi"}],
                                        "isError": False}
        assert replies[4]["result"]["isError"] is True
        assert replies[5]["error"]["code"] == -32601
    finally:
        relay.close()


# --- runner ------------------------------------------------------------------------------------

STREAM = [
    {"type": "system", "subtype": "init", "model": "claude-sonnet-5-5", "cwd": "C:/Users/x",
     "tools": ["mcp__secagent__echo"]},
    {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "echo"}]}},
    {"type": "user", "message": {"content": [{"type": "tool_result", "content": "hi"}]}},
    {"type": "result", "subtype": "success", "is_error": False, "num_turns": 3,
     "total_cost_usd": 0.0125, "result": "done",
     "usage": {"input_tokens": 6, "cache_read_input_tokens": 3000,
               "cache_creation_input_tokens": 1800, "output_tokens": 280}},
]


def test_summarize_reads_totals_and_errors():
    run = summarize([json.dumps(m) for m in STREAM] + ["not json"])
    assert (run.ok, run.turns, run.tokens_in, run.tokens_out, run.cost_usd, run.model) == (
        True, 3, 4806, 280, 0.0125, "claude-sonnet-5-5")
    capped = dict(STREAM[-1], subtype="error_max_turns", is_error=True)
    assert summarize([json.dumps(capped)]).ok  # the step limit, not a failure
    failed = dict(STREAM[-1], subtype="error_during_execution", is_error=True,
                  result="usage limit sk-ant-" + "a" * 30)
    run = summarize([json.dumps(failed)])
    assert not run.ok and "error_during_execution" in run.error and "sk-ant-" + "a" * 30 \
        not in run.error
    assert not summarize([]).ok


def test_runner_command_is_isolated(tmp_path):
    seen = {}

    def fake_run(cmd, **kw):
        seen.update(cmd=cmd, **kw)
        config = json.loads(Path(cmd[cmd.index("--mcp-config") + 1]).read_text(encoding="utf-8"))
        seen["config"] = config
        seen["system"] = Path(cmd[cmd.index("--system-prompt-file") + 1]).read_text(
            encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "\n".join(json.dumps(m) for m in STREAM), "")

    runner = ClaudeMcpRunner(mcp_settings(), claude_bin="claude", run=fake_run)
    runner.transcript_dir = tmp_path / "t"
    run = runner.run_session(system="SYS", prompt="USER", tools=SCHEMA,
                             call=lambda n, a: "", max_turns=13, timeout_s=10)
    cmd = seen["cmd"]
    assert run.ok and run.turns == 3
    assert cmd[cmd.index("--tools") + 1] == ""
    assert cmd[cmd.index("--allowedTools") + 1] == "mcp__secagent"
    assert cmd[cmd.index("--permission-mode") + 1] == "dontAsk"
    assert cmd[cmd.index("--max-turns") + 1] == "13"
    assert cmd[cmd.index("--model") + 1] == "claude-sonnet-5-5"
    assert {"--strict-mcp-config", "--no-session-persistence",
            "--disable-slash-commands"} <= set(cmd)
    assert seen["input"] == "USER" and seen["system"] == "SYS" and seen["timeout"] == 60
    server = seen["config"]["mcpServers"]["secagent"]
    assert server["args"] == ["-I", str(BRIDGE)] and set(server["env"]) == {
        "SECAGENT_RELAY_PORT", "SECAGENT_RELAY_TOKEN"}
    assert not Path(seen["cwd"]).exists()  # the session's temporary directory is removed
    saved = (tmp_path / "t" / "session-01.jsonl").read_text(encoding="utf-8")
    assert "C:/Users/x" not in saved and '"init"' not in saved and "tool_use" in saved


def test_runner_without_claude_cli_fails_cleanly(monkeypatch):
    monkeypatch.delenv("CLAUDE_BIN", raising=False)
    monkeypatch.setattr("shutil.which", lambda name: None)
    run = ClaudeMcpRunner(mcp_settings()).run_session(
        system="", prompt="", tools=[], call=lambda n, a: "", max_turns=1, timeout_s=1)
    assert not run.ok and "CLAUDE_BIN" in run.error


# --- the review session driven through claude-mcp -----------------------------------------


def test_session_runs_through_the_runner(tmp_path):
    runner = FakeRunner([[("read_file", json.dumps({"path": SERVICE})),
                          ("submit_verdict", verdict("F1")), ("finish", "{}")]])
    out = run_review(context(tmp_path), runner, Trace(None))
    (session,) = runner.sessions
    assert out.verdicts["F1"].verdict == "TP" and out.error is None and not out.limit_hit
    assert (out.llm_calls, out.tool_calls, out.cost_usd, out.model) == (
        3, 3, 0.01, "claude-sonnet-5-5")
    assert "untrusted-code" in session["system"] and "+    audit(item_id)" in session["prompt"]
    assert {"read_file", "list_routes", "submit_verdict", "report_finding", "finish"} <= set(
        session["tools"])
    assert session["max_turns"] == 13 and "<untrusted-code" in session["results"][0]


def test_step_limit_then_forced_session_refuses_read_tools(tmp_path):
    runner = FakeRunner([[("read_file", json.dumps({"path": SERVICE}))],
                         [("read_file", json.dumps({"path": SERVICE})),
                          ("submit_verdict", verdict("F1")), ("finish", "{}")]],
                        subtypes=["error_max_turns", "success"])
    out = run_review(context(tmp_path), runner, Trace(None))
    forced = runner.sessions[1]
    assert out.limit_hit and out.verdicts["F1"].verdict == "TP"
    assert forced["max_turns"] == 2 and forced["results"][0] == STEP_EXHAUSTED
    assert "Đã hết số bước" in forced["prompt"] and "đừng nộp lại" in forced["prompt"]


def test_coverage_check_asks_again_in_a_new_session(tmp_path):
    runner = FakeRunner([[("submit_verdict", verdict("F1")), ("finish", "{}"),
                          ("finish", "{}")],
                         [("submit_verdict", verdict("F2")), ("finish", "{}")]])
    ctx = context(tmp_path, n=2)
    out = run_review(ctx, runner, Trace(None))
    assert set(out.verdicts) == {"F1"}
    assert ensure_coverage(out, ctx.clusters, ctx.settings) == 1
    assert set(out.verdicts) == {"F1", "F2"}
    assert "Chưa có kết luận cho: F2" in runner.sessions[1]["prompt"]


def test_single_shot_offers_only_submission_tools(tmp_path):
    runner = FakeRunner([[("submit_verdict", verdict("F1")), ("finish", "{}")]])
    run_review(context(tmp_path, strategy="single-shot"), runner, Trace(None))
    (session,) = runner.sessions
    assert session["tools"] == ["submit_verdict", "report_finding", "finish"]
    assert session["max_turns"] == 2 and "    1| def load_item" in session["prompt"]


def test_runner_failure_keeps_submitted_verdicts(tmp_path):
    class Failing(FakeRunner):
        def run_session(self, **kw):
            super().run_session(**kw)
            return SessionRun(ok=False, error="claude-mcp: hết thời gian")

    out = run_review(context(tmp_path), Failing([[("submit_verdict", verdict("F1"))]]),
                     Trace(None))
    assert out.error == "claude-mcp: hết thời gian" and out.verdicts["F1"].verdict == "TP"
