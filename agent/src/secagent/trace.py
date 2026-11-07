"""trace.jsonl: one JSON line per agent event (LLM call, tool call, decision), redacted."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from secagent.context.redact import redact

MAX_TEXT = 4000


def _clean(value):
    if isinstance(value, str):
        text = redact(value)
        return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + "…"
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


class Trace:
    def __init__(self, path: Path | None) -> None:
        self._file = None
        if path is not None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            # Kept open for the whole run (one line per event); close() releases it.
            self._file = open(path, "a", encoding="utf-8")

    def event(self, kind: str, **data) -> None:
        if self._file is None:
            return
        record = {"t": datetime.now(UTC).isoformat(timespec="seconds"), "kind": kind,
                  **_clean(data)}
        self._file.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        self._file.flush()

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
