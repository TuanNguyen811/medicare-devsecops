"""Data shapes shared by the agent phases and report.json (spec 4.3, roadmap Contract 2)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
VerdictKind = Literal["TP", "FP", "NEEDS_REVIEW"]
SEVERITY_RANK: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

CWE_PATTERN = r"^CWE-\d+$"
OWASP_PATTERN = r"^A(0[1-9]|10)$"
RULE_PATTERN = r"^R-\d{2}$"


class Evidence(BaseModel):
    file: str = Field(description="Path relative to the repository root")
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str = Field(default="", description="Exact code copied from those lines")

    @model_validator(mode="after")
    def _ordered(self) -> Evidence:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self


class Fix(BaseModel):
    description: str
    patch: str = Field(default="", description="Unified diff from the repo root (a/ b/ prefixes)")
    validated: bool | None = None
    validation_note: str = ""


class VerdictArgs(BaseModel):
    """Arguments of the submit_verdict tool: the verdict for one finding cluster."""

    cluster_id: str
    verdict: VerdictKind
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    cwe: str | None = Field(default=None, pattern=CWE_PATTERN)
    owasp: str | None = Field(default=None, pattern=OWASP_PATTERN)
    violated_rule: str | None = Field(default=None, pattern=RULE_PATTERN)
    reasoning: str = Field(min_length=1)
    evidence: list[Evidence] = Field(default_factory=list)
    exploit_scenario: str = ""
    fix: Fix | None = None


class NewFindingArgs(BaseModel):
    """Arguments of the report_finding tool: a vulnerability no scanner reported."""

    title: str = Field(min_length=1)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    cwe: str = Field(pattern=CWE_PATTERN)
    owasp: str | None = Field(default=None, pattern=OWASP_PATTERN)
    violated_rule: str | None = Field(default=None, pattern=RULE_PATTERN)
    reasoning: str = Field(min_length=1)
    evidence: list[Evidence] = Field(min_length=1)
    exploit_scenario: str = ""
    fix: Fix | None = None


class ReportEntry(BaseModel):
    finding_id: str
    finding_ids: list[str]
    source: str
    title: str
    verdict: VerdictKind
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    cwe: str | None = None
    owasp: str | None = None
    violated_rule: str | None = None
    reasoning: str
    evidence: list[Evidence] = Field(default_factory=list)
    exploit_scenario: str = ""
    fix: Fix | None = None
    file: str
    line: int


class Meta(BaseModel):
    model: str
    strategy: str
    started_at: str
    duration_s: float
    llm_calls: int
    tool_calls: int
    tokens_in: int
    tokens_out: int
    cost_usd: float
    step_limit: int
    limit_hit: bool
    uncovered_before_check: int
    error: str | None = None


class Report(BaseModel):
    meta: Meta
    findings: list[ReportEntry]
