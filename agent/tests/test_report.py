from secagent.context.diff import FileDiff, PrDiff
from secagent.models import Evidence, Fix, Meta, Report, ReportEntry
from secagent.report.github import build_review
from secagent.report.markdown import MARKER, render_failure, render_markdown
from secagent.report.sarif_out import to_sarif

SERVICE = "app/medicare/demo/service.py"
OLD = "    return db.execute(text(f\"SELECT * FROM items WHERE name = '{q}'\"))"
NEW = '    return db.execute(text("SELECT * FROM items WHERE name = :q"), {"q": q})'


def patch(line: int, old=(OLD,), new=(NEW,)) -> str:
    body = "".join(f"-{x}\n" for x in old) + "".join(f"+{x}\n" for x in new)
    return (f"--- a/{SERVICE}\n+++ b/{SERVICE}\n"
            f"@@ -{line},{len(old)} +{line},{len(new)} @@\n{body}")


def meta(**kw) -> Meta:
    data = {"model": "deepseek-chat", "strategy": "agent",
            "started_at": "2026-11-07T10:00:00+00:00",
            "duration_s": 12.5, "llm_calls": 4, "tool_calls": 6, "tokens_in": 1200,
            "tokens_out": 300, "cost_usd": 0.0005, "step_limit": 13, "limit_hit": False,
            "uncovered_before_check": 0}
    data.update(kw)
    return Meta(**data)


def entry(verdict="TP", source="semgrep", line=15, **kw) -> ReportEntry:
    finding_id = f"{source}:r:{SERVICE}:{line}"
    data = {"finding_id": finding_id, "finding_ids": [finding_id],
            "source": source, "title": "r (semgrep)", "verdict": verdict, "confidence": 0.9,
            "severity": "HIGH", "cwe": "CWE-89", "owasp": "A05", "reasoning": "SQL ghép chuỗi",
            "evidence": [Evidence(file=SERVICE, start_line=line, end_line=line)],
            "exploit_scenario": "q = ' OR 1=1 --",
            "fix": Fix(description="Dùng tham số ràng buộc", patch=patch(line)),
            "file": SERVICE, "line": line}
    data.update(kw)
    return ReportEntry(**data)


def test_markdown_report():
    fenced = entry(fix=Fix(description="d", patch=patch(15) + "+```\n"))
    fp = entry("FP", line=3, reasoning="Hằng số, không phải dữ liệu người dùng", fix=None)
    agent = entry(source="agent", finding_id="agent:1", finding_ids=[], title="IDOR khi xuất")
    text = render_markdown(Report(meta=meta(), findings=[fenced, agent, fp]), head_sha="abc123")
    assert text.splitlines()[0] == MARKER
    assert "````diff" in text and "\n````" in text
    assert "<details>" in text and "Hằng số, không phải dữ liệu người dùng" in text
    assert "IDOR khi xuất" in text and "deepseek-chat" in text and "chưa kiểm chứng" in text
    assert text.index("<details>") > text.index("SQL ghép chuỗi")


def test_markdown_report_is_capped_and_redacted():
    secret = "AKIA" + "Q" * 16
    many = [entry(line=i, reasoning=f"{secret} " + "x" * 2000) for i in range(1, 80)]
    text = render_markdown(Report(meta=meta(), findings=many))
    assert len(text) <= 60_000 and "cắt bớt" in text and secret not in text


def test_render_failure():
    text = render_failure("APIConnectionError")
    assert text.startswith(MARKER) and "traditional" in text and "APIConnectionError" in text


def test_sarif_out_only_agent_findings():
    report = Report(meta=meta(), findings=[
        entry(), entry(source="agent", finding_id="agent:1", finding_ids=[], title="IDOR"),
        entry("FP", source="agent", finding_id="agent:2", finding_ids=[], title="noise"),
        entry("NEEDS_REVIEW", source="agent", finding_id="agent:3", finding_ids=[],
              title="maybe", severity="MEDIUM", cwe=None),
    ])
    run = to_sarif(report)["runs"][0]
    assert run["tool"]["driver"]["name"] == "secagent"
    assert [(r["ruleId"], r["level"], r["properties"]["security-severity"])
            for r in run["results"]] == [("secagent/CWE-89", "error", "8.0"),
                                         ("secagent/finding", "warning", "5.5")]
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location == {"artifactLocation": {"uri": SERVICE}, "region": {"startLine": 15}}


def test_build_review_suggestion():
    diff = PrDiff({SERVICE: FileDiff(SERVICE, {14, 15})})
    head = ["x"] * 14 + [OLD]
    review = build_review(Report(meta=meta(), findings=[entry()]), diff, "abc123",
                          lambda path: head)
    (comment,) = review["comments"]
    assert review["commit_id"] == "abc123" and review["event"] == "COMMENT"
    assert "secagent-review:abc123" in review["body"]
    assert comment["path"] == SERVICE and comment["line"] == 15 and comment["side"] == "RIGHT"
    assert "start_line" not in comment
    assert f"```suggestion\n{NEW}\n```" in comment["body"]


def test_build_review_multi_line_and_outside_the_pr():
    two = entry(fix=Fix(description="d", patch=patch(14, old=("a", OLD), new=(NEW,))))
    review = build_review(Report(meta=meta(), findings=[two]),
                          PrDiff({SERVICE: FileDiff(SERVICE, {14, 15})}), "h",
                          lambda path: ["x"] * 13 + ["a", OLD])
    (comment,) = review["comments"]
    assert (comment["start_line"], comment["line"]) == (14, 15)
    outside = PrDiff({SERVICE: FileDiff(SERVICE, {30})})
    head = ["x"] * 14 + [OLD]
    assert build_review(Report(meta=meta(), findings=[entry()]), outside, "h",
                        lambda path: head) is None
    fp = entry("FP")
    assert build_review(Report(meta=meta(), findings=[fp]),
                        PrDiff({SERVICE: FileDiff(SERVICE, {15})}), "h",
                        lambda path: head) is None
