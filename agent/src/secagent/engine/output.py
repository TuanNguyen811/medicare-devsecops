"""The JSON document the Claude Code engine must return as its final answer."""

from __future__ import annotations

from pydantic import BaseModel, Field

from secagent.models import NewFindingArgs, VerdictArgs


class EngineOutput(BaseModel):
    verdicts: list[VerdictArgs] = Field(default_factory=list)
    new_findings: list[NewFindingArgs] = Field(default_factory=list)
