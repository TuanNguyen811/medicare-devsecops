"""LLM mode `claude-mcp` (spec 5.5): Claude Code on this machine is the model.

secagent keeps the review session: tool registry, submissions, trace, budgets. Each session runs
one `claude -p` process that sees no built-in tool at all (`--tools ""`), only the session's
own tools, served by an MCP server (mcp_bridge.py) that relays every call back to this process
over a loopback socket guarded by a per-session token. Claude Code's own login is used: no API
key is read, stored or forwarded. Never used in CI (config.py refuses it there).
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shutil
import signal
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
# One fixed, empty working directory for every session: Claude Code records each working
# directory it sees in the user's config, so a new one per session would grow it per run.
CWD = Path(tempfile.gettempdir()) / "secagent-claude-mcp"
MIN_TIMEOUT_S = 30.0
KILL_GRACE_S = 10.0
ERROR_TEXT_LIMIT = 200
STDERR_LIMIT = 300
RESULT_KEYS = ("type", "subtype", "is_error", "num_turns", "duration_ms", "total_cost_usd",
               "usage", "modelUsage")
# Variables never handed to Claude Code: an API key there would bill the API instead of the
# login, and the driving session's own Claude Code variables must not leak into the child.
_DROPPED_ENV = re.compile(r"^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|LLM_API_KEY|CLAUDECODE"
                          r"|CLAUDE_CODE_ENTRYPOINT|CLAUDE_CODE_SSE_PORT|SECAGENT_RELAY_.*)$",
                          re.IGNORECASE)
_USAGE_LIMIT = re.compile(r"usage limit|rate limit|limit reached|quota|\b429\b", re.IGNORECASE)
_AUTH = re.compile(r"log ?in|logged|auth|credential|\b401\b|\b403\b", re.IGNORECASE)

ToolCaller = Callable[[str, str], str]  # (tool name, raw JSON arguments) -> result text


@dataclass
class Completed:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


Spawn = Callable[[list[str], str, Path, dict[str, str], float], Completed]


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
    stderr_tail: str = ""


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
        self._conns: list[socket.socket] = []
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
            with self._lock:
                if self._closed:
                    conn.close()
                    return
                self._conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
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
        except OSError:
            return  # closed by close(), or the bridge went away

    def _answer(self, request: dict) -> dict:
        if request.get("op") == "list":
            return {"tools": self.tools}
        if request.get("op") == "call":
            name, arguments = str(request.get("name", "")), request.get("arguments")
            raw = arguments if isinstance(arguments, str) else json.dumps(arguments or {})
            with self._lock:
                if self._closed:  # the session is over: nothing may change its outcome now
                    return {"text": "ERROR: phiên review đã kết thúc", "error": True}
                text = self.call(name, raw)
            return {"text": text, "error": text.startswith("ERROR")}
        return {"text": "ERROR: unknown operation", "error": True}

    def close(self) -> None:
        with self._lock:
            self._closed = True
            conns, self._conns = self._conns, []
        self._sock.close()
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()


def child_env(environ: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environ is None else environ
    return {k: v for k, v in source.items() if not _DROPPED_ENV.match(k)}


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill Claude Code and its children (on Windows `claude.cmd` starts `claude.exe`)."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                       capture_output=True, check=False)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()


def spawn(cmd: list[str], stdin: str, cwd: Path, env: dict[str, str],
          timeout_s: float) -> Completed:
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            errors="replace", cwd=cwd, env=env,
                            start_new_session=os.name != "nt")
    try:
        out, err = proc.communicate(stdin, timeout=timeout_s)
        return Completed(proc.returncode, out or "", err or "")
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=KILL_GRACE_S)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        return Completed(None, out or "", err or "", timed_out=True)


def _messages(lines: list[str]) -> list[dict]:
    items = []
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            items.append(item)
    return items


def _error_kind(text: str) -> str:
    if _USAGE_LIMIT.search(text):
        return "usage-limit"
    if _AUTH.search(text):
        return "auth"
    return "error"


def summarize(lines: list[str]) -> SessionRun:
    """Turns, tokens, cost and model from `claude -p --output-format stream-json` output.

    Without a final result message (killed on timeout), the turns are the assistant messages
    seen so far and the error is left to the caller.
    """
    messages = _messages(lines)
    model = next((m.get("model") for m in messages
                  if m.get("type") == "system" and m.get("subtype") == "init" and m.get("model")),
                 None)
    model = model if isinstance(model, str) else None
    results = [m for m in messages if m.get("type") == "result"]
    if not results:
        turns = sum(1 for m in messages if m.get("type") == "assistant")
        return SessionRun(ok=False, error="claude-mcp: error: không có kết quả từ Claude Code",
                          turns=turns, model=model)
    result = results[-1]
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
        model=model,
    )
    # Running out of turns is the step limit, handled by the caller like in API mode.
    if result.get("is_error") and subtype != "error_max_turns":
        text = result.get("result") if isinstance(result.get("result"), str) else ""
        run.ok = False
        run.error = redact(f"claude-mcp: {_error_kind(text)}: {subtype or 'error'}: "
                           f"{text}"[:ERROR_TEXT_LIMIT])
    return run


class ClaudeMcpRunner:
    """Runs one review session per call; see the module docstring."""

    def __init__(self, settings: Settings, *, claude_bin: str | None = None,
                 spawn: Spawn = spawn) -> None:
        self.settings = settings
        self.claude_bin = claude_bin or os.environ.get("CLAUDE_BIN") or shutil.which("claude")
        self._spawn = spawn
        self.transcript_dir: Path | None = None
        self._count = 0

    def run_session(self, *, system: str, prompt: str, tools: list[dict], call: ToolCaller,
                    max_turns: int, timeout_s: float) -> SessionRun:
        if not self.claude_bin:
            return SessionRun(ok=False, error="claude-mcp: error: không tìm thấy Claude Code CLI "
                                              "(đặt CLAUDE_BIN)")
        relay = ToolRelay(mcp_tools(tools), call)
        work = Path(tempfile.mkdtemp(prefix="secagent-claude-mcp-session-"))
        try:
            CWD.mkdir(parents=True, exist_ok=True)
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
                done = self._spawn(cmd, prompt, CWD, child_env(),
                                   max(MIN_TIMEOUT_S, timeout_s))
            except OSError as exc:
                return SessionRun(ok=False, error=f"claude-mcp: error: {type(exc).__name__}")
        finally:
            relay.close()  # no tool call may land after this point
            shutil.rmtree(work, ignore_errors=True)
        lines = done.stdout.splitlines()
        self._save(lines)
        run = summarize(lines)
        run.stderr_tail = redact(done.stderr.strip()[-STDERR_LIMIT:])
        if done.timed_out:
            run.ok, run.error = False, "claude-mcp: timeout: hết thời gian của phiên"
        elif not run.ok and run.subtype is None and done.returncode:
            run.error = f"claude-mcp: error: Claude Code thoát mã {done.returncode}"
        return run

    def _save(self, lines: list[str]) -> None:
        """Keep the conversation (model turns, tool results) and the totals, nothing about the
        machine: the init message (paths, environment, account) is left out, since benchmark
        transcripts are committed."""
        if self.transcript_dir is None:
            return
        kept = []
        for item in _messages(lines):
            if item.get("type") in ("assistant", "user"):
                kept.append({"type": item["type"], "message": item.get("message")})
            elif item.get("type") == "result":
                kept.append({k: item.get(k) for k in RESULT_KEYS})
        self._count += 1
        self.transcript_dir.mkdir(parents=True, exist_ok=True)
        path = self.transcript_dir / f"session-{self._count:02d}.jsonl"
        path.write_text("".join(json.dumps(k, ensure_ascii=False) + "\n" for k in kept),
                        encoding="utf-8")
