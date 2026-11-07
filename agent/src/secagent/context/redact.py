"""Mask secrets before any text reaches the LLM, the trace or a report (spec 4.6)."""

from __future__ import annotations

import re

REDACTED = "«REDACTED»"

_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),  # OpenAI / Anthropic / DeepSeek keys
    re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}"),  # Stripe
    re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}"),  # Slack
)
# scheme://user:password@host — keep the user and host, hide the password.
_URL_PASSWORD = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)")
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
    text = _URL_PASSWORD.sub(lambda m: f"{m[1]}{REDACTED}{m[3]}", text)
    return _ASSIGNMENT.sub(lambda m: f"{m[1]}{m[2]}{m[3]}{REDACTED}{m[3]}", text)


def redact_value(value):
    """Redact every string inside nested dicts and lists (report.json, review.json)."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value


def mask_line() -> str:
    """Replacement for a whole source line that Gitleaks reported."""
    return "«REDACTED: dòng bị Gitleaks báo»"
