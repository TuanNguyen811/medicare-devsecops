"""agent.sarif: the agent's own findings for the GitHub Security tab (category ai-agent).

Only vulnerabilities the agent found itself are exported; scanner findings are already uploaded
by their own jobs. Never write this file into the gate's sarif/ directory.
"""

from __future__ import annotations

from secagent.context.redact import redact
from secagent.models import Report

SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0"}
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def to_sarif(report: Report) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for e in report.findings:
        if e.source != "agent" or e.verdict not in ("TP", "NEEDS_REVIEW"):
            continue
        rule_id = f"secagent/{e.cwe or 'finding'}"
        rules.setdefault(rule_id, {
            "id": rule_id, "name": rule_id, "shortDescription": {"text": redact(e.title)},
            "properties": {"tags": ["security", *([e.cwe] if e.cwe else [])],
                           "security-severity": SECURITY_SEVERITY[e.severity]},
        })
        results.append({
            "ruleId": rule_id, "level": LEVEL[e.severity],
            "message": {"text": redact(f"{e.title}: {e.reasoning}")[:1000]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": e.file},
                                                "region": {"startLine": max(1, e.line)}}}],
            "properties": {"security-severity": SECURITY_SEVERITY[e.severity],
                           "verdict": e.verdict, "confidence": e.confidence},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "secagent", "version": "0.1.0",
            "informationUri": "https://github.com/TuanNguyen811/medicare-devsecops",
            "rules": list(rules.values())}},
            "results": results}],
    }
