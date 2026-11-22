"""LLM mode `claude-mcp` (spec addendum 4.2): Claude Code on this machine is the model.

secagent keeps the review session: tool registry, submissions, trace, budgets. Each session runs
one `claude -p` process that sees no built-in tool at all (`--tools ""`), only the session's
own tools, served by an MCP server (mcp_bridge.py) that relays every call back to this process
over a loopback socket guarded by a one-time token. Claude Code's own login is used: no API key
is read, stored or forwarded. Never used in CI (config.py refuses `--mode ci`).
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from secagent.config import Settings
from secagent.context.redact import redact

BRIDGE = Path(__file__).resolve().parent.parent / "mcp_bridge.py"
SERVER = "secagent"
# Each session is a fresh, isolated process: no user settings, hooks, plugins, MCP servers,
# slash commands or saved history; permissions limited to the bridge's tools.
ISOLATION = ("--setting-sources", "project", "--strict-mcp-config", "--disable-slash-commands",
             "--no-session-persistence", "--permission-mode", "dontAsk")
MIN_TIMEOUT_S = 60.0
ERROR_TEXT_LIMIT = 200
RESULT_KEYS = ("type", "subtype", "is_error", "num_turns", "duration_ms", "total_cost_usd",
               "usage", "modelUsage")

ToolCaller = Callable[[str, str], str]  # (tool name, raw JSON arguments) -> result text


@dataclass
class SessionRun:
    ok: bool
    error: str | None = None
    subtype: str | None = None  # "success", "error_max_turns", ...
    turns: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    model: str | None = None


def mcp_tools(schemas: list[dict]) -> list[dict]:
    """OpenAI-format function schemas (ToolRegistry.schemas) as MCP tool definitions."""
    return [{"name": s["function"]["name"], "description": s["function"]["description"],
             "inputSchema": s["function"]["parameters"]} for s in schemas]


class ToolRelay:
    """Loopback server answering the bridge: `list` the tools, `call` one (serialised)."""

    def __init__(self, tools: list[dict], call: ToolCaller) -> None:
        self.tools, self.call = tools, call
        self.token = secrets.token_urlsafe(32)
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._closed = False
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        while not self._closed:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn, conn.makefile("rwb") as stream:
            for raw in stream:
                try:
                    request = json.loads(raw)
                except ValueError:
                    return
                if not isinstance(request, dict) or not hmac.compare_digest(
                        str(request.get("token", "")), self.token):
                    return  # wrong token: drop the connection without answering
                stream.write(json.dumps(self._answer(request)).encode() + b"\n")
                stream.flush()

    def _answer(self, request: dict) -> dict:
        if request.get("op") == "list":
            return {"tools": self.tools}
        if request.get("op") == "call":
            name, arguments = str(request.get("name", "")), request.get("arguments")
            raw = arguments if isinstance(arguments, str) else json.dumps(arguments or {})
            with self._lock:
                text = self.call(name, raw)
            return {"text": text, "error": text.startswith("ERROR")}
        return {"text": "ERROR: unknown operation", "error": True}

    def close(self) -> None:
        self._closed = True
        self._sock.close()


def summarize(lines: list[str]) -> SessionRun:
    """Turns, tokens, cost and model from `claude -p --output-format stream-json` output."""
    messages = []
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            messages.append(item)
    results = [m for m in messages if m.get("type") == "result"]
    if not results:
        return SessionRun(ok=False, error="claude-mcp: không có kết quả từ Claude Code")
    result = results[-1]
    model = next((m.get("model") for m in messages
                  if m.get("type") == "system" and m.get("subtype") == "init" and m.get("model")),
                 None)
    usage = result.get("usage") if isinstance(result.get("usage"), dict) else {}

    def n(key: str) -> int:
        value = usage.get(key)
        return value if isinstance(value, int) else 0

    subtype = result.get("subtype") if isinstance(result.get("subtype"), str) else None
    cost = result.get("total_cost_usd")
    run = SessionRun(
        ok=True, subtype=subtype,
        turns=result.get("num_turns") if isinstance(result.get("num_turns"), int) else 0,
        tokens_in=(n("input_tokens") + n("cache_read_input_tokens")
                   + n("cache_creation_input_tokens")),
        tokens_out=n("output_tokens"),
        cost_usd=float(cost) if isinstance(cost, int | float) else 0.0,
        model=model if isinstance(model, str) else None,
    )
    # Running out of turns is the step limit, handled by the caller like in API mode.
    if result.get("is_error") and subtype != "error_max_turns":
        text = result.get("result") if isinstance(result.get("result"), str) else ""
        run.ok = False
        run.error = redact(f"claude-mcp: {subtype or 'error'}: {text}"[:ERROR_TEXT_LIMIT])
    return run


class ClaudeMcpRunner:
    """Runs one review session per call; see the module docstring."""

    def __init__(self, settings: Settings, *, claude_bin: str | None = None,
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None:
        self.settings = settings
        self.claude_bin = claude_bin or os.environ.get("CLAUDE_BIN") or shutil.which("claude")
        self._run = run
        self.transcript_dir: Path | None = None
        self._count = 0

    def run_session(self, *, system: str, prompt: str, tools: list[dict], call: ToolCaller,
                    max_turns: int, timeout_s: float) -> SessionRun:
        if not self.claude_bin:
            return SessionRun(ok=False, error="claude-mcp: không tìm thấy Claude Code CLI "
                                              "(đặt CLAUDE_BIN)")
        relay = ToolRelay(mcp_tools(tools), call)
        work = Path(tempfile.mkdtemp(prefix="secagent-claude-mcp-"))
        try:
            (work / "system.md").write_text(system, encoding="utf-8")
            (work / "mcp.json").write_text(json.dumps({"mcpServers": {SERVER: {
                "type": "stdio", "command": sys.executable, "args": ["-I", str(BRIDGE)],
                "env": {"SECAGENT_RELAY_PORT": str(relay.port),
                        "SECAGENT_RELAY_TOKEN": relay.token},
            }}}), encoding="utf-8")
            cmd = [self.claude_bin, "-p", "--model", self.settings.model,
                   "--system-prompt-file", str(work / "system.md"),
                   "--tools", "", "--mcp-config", str(work / "mcp.json"),
                   "--allowedTools", f"mcp__{SERVER}", "--max-turns", str(max(1, max_turns)),
                   *ISOLATION, "--output-format", "stream-json", "--verbose"]
            try:
                done = self._run(cmd, input=prompt, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", cwd=work,
                                 timeout=max(MIN_TIMEOUT_S, timeout_s))
            except subprocess.TimeoutExpired:
                return SessionRun(ok=False, error="claude-mcp: hết thời gian")
            except OSError as exc:
                return SessionRun(ok=False, error=f"claude-mcp: {type(exc).__name__}")
            lines = (done.stdout or "").splitlines()
            self._save(lines)
            run = summarize(lines)
            if run.ok is False and run.error and not run.subtype and done.returncode:
                run.error = f"claude-mcp: Claude Code thoát mã {done.returncode}"
            return run
        finally:
            relay.close()
            shutil.rmtree(work, ignore_errors=True)

    def _save(self, lines: list[str]) -> None:
        """Keep the conversation (model turns, tool results) and the totals, nothing about the
        machine: the init message (paths, environment, account) is left out, since benchmark
        transcripts are committed."""
        if self.transcript_dir is None:
            return
        kept = []
        for line in lines:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if not isinstance(item, dict):
                continue
            if item.get("type") in ("assistant", "user"):
                kept.append({"type": item["type"], "message": item.get("message")})
            elif item.get("type") == "result":
                kept.append({k: item.get(k) for k in RESULT_KEYS})
        self._count += 1
        self.transcript_dir.mkdir(parents=True, exist_ok=True)
        path = self.transcript_dir / f"session-{self._count:02d}.jsonl"
        path.write_text("".join(json.dumps(k, ensure_ascii=False) + "\n" for k in kept),
                        encoding="utf-8")
