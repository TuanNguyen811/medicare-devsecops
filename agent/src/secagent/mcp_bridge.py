"""MCP server (stdio) for LLM mode `claude-mcp`: relays the session's tools to secagent.

Started by Claude Code from the per-session MCP config written by llm/claude_mcp.py, as
`python -I mcp_bridge.py`, with SECAGENT_RELAY_PORT and SECAGENT_RELAY_TOKEN in its environment.
It implements only what Claude Code needs: initialize, tools/list, tools/call, ping. Every tool
call is forwarded to the secagent process (127.0.0.1, one-time token), which runs it with the
same ToolRegistry as API mode. Standard library only; holds no state and reads no file.
"""

from __future__ import annotations

import json
import os
import socket
import sys

PROTOCOL_VERSION = "2025-06-18"


class Relay:
    def __init__(self, port: int, token: str) -> None:
        self.token = token
        self.conn = socket.create_connection(("127.0.0.1", port), timeout=600)
        self.stream = self.conn.makefile("rwb")

    def ask(self, request: dict) -> dict:
        self.stream.write(json.dumps({**request, "token": self.token}).encode() + b"\n")
        self.stream.flush()
        line = self.stream.readline()
        if not line:
            raise ConnectionError("secagent closed the relay")
        return json.loads(line)


def handle(message: dict, relay: Relay) -> dict | None:
    """The JSON-RPC response to one message, or None for a notification."""
    if "id" not in message:
        return None
    method, params = message.get("method"), message.get("params") or {}
    if method == "initialize":
        result = {"protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "secagent", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": relay.ask({"op": "list"})["tools"]}
    elif method == "tools/call":
        answer = relay.ask({"op": "call", "name": params.get("name", ""),
                            "arguments": params.get("arguments") or {}})
        result = {"content": [{"type": "text", "text": answer["text"]}],
                  "isError": bool(answer.get("error"))}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": message["id"],
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def main() -> int:
    relay = Relay(int(os.environ["SECAGENT_RELAY_PORT"]), os.environ["SECAGENT_RELAY_TOKEN"])
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    for line in stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict):
            continue
        response = handle(message, relay)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
            stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
