"""Mask secrets before any text reaches the LLM, the trace or a report (spec 4.6)."""

from __future__ import annotations

import re

REDACTED = "«REDACTED»"

_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
)
# name = "value" / name: 'value' / "name": "value" where the name looks like a credential.
_ASSIGNMENT = re.compile(
    r"(?i)\b([\w-]*(?:password|passwd|secret|token|api[_-]?key)[\w-]*)"
    r"(['\"]?\s*[:=]\s*)(['\"])([^'\"\n]{4,})\3"
)


def redact(text: str) -> str:
    if not text:
        return text
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    return _ASSIGNMENT.sub(lambda m: f"{m[1]}{m[2]}{m[3]}{REDACTED}{m[3]}", text)


def mask_line() -> str:
    """Replacement for a whole source line that Gitleaks reported."""
    return "«REDACTED: dòng bị Gitleaks báo»"
