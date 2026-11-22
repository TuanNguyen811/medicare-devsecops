from secagent.context.diff import FileDiff, PrDiff
from secagent.models import Evidence, Fix, Meta, Report, ReportEntry
from secagent.report.github import build_review
from secagent.report.markdown import MARKER, render_failure, render_markdown
from secagent.report.sarif_out import to_sarif

SERVICE = "app/medicare/demo/service.py"
OLD = "    return db.execute(text(f\"SELECT * FROM items WHERE name = '{q}'\"))"
FIX = "Dùng tham số ràng buộc: text(\"... WHERE name = :q\") với {\"q\": q}"


def meta(**kw) -> Meta:
    data = {"model": "claude-sonnet-5-5", "strategy": "agent",
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
            "fix": Fix(description=FIX),
            "file": SERVICE, "line": line}
    data.update(kw)
    return ReportEntry(**data)


def test_markdown_report():
    tp = entry()
    fp = entry("FP", line=3, reasoning="Hằng số, không phải dữ liệu người dùng", fix=None)
    agent = entry(source="agent", finding_id="agent:1", finding_ids=[], title="IDOR khi xuất")
    text = render_markdown(Report(meta=meta(), findings=[tp, agent, fp]), head_sha="abc123")
    assert text.splitlines()[0] == MARKER
    assert f"**Đề xuất sửa:** {FIX}" in text and "```" not in text
    assert "<details>" in text and "Hằng số, không phải dữ liệu người dùng" in text
    assert "IDOR khi xuất" in text and "claude-sonnet-5-5" in text
    assert text.index("<details>") > text.index("SQL ghép chuỗi")


def dast(route: str, rule: str = "10020", verdict: str = "TP", sev: str = "MEDIUM") -> ReportEntry:
    alert = entry(verdict, source="zap", finding_id=f"zap:{rule}:{route}",
                  finding_ids=[f"zap:{rule}:{route}"], title=f"{rule} (zap)", severity=sev,
                  cwe="CWE-1021", reasoning="Ứng dụng không đặt X-Frame-Options.",
                  file=f"dast:{route}", fix=Fix(description="Thêm middleware đặt X-Frame-Options: DENY."))
    return alert.model_copy(update={"line": 0, "evidence": []})  # as DAST entries come


def test_clean_pr_with_app_wide_dast_alerts_reads_as_clean():
    """Header warnings of the running app are not reported as the PR's vulnerabilities."""
    fp = entry("FP", line=3, reasoning="Hằng số, không phải dữ liệu người dùng", fix=None)
    alerts = [dast("GET /"), dast("GET /login"), dast("GET /health", rule="10021", sev="LOW")]
    text = render_markdown(Report(meta=meta(), findings=[fp, *alerts]), head_sha="abc123")
    summary = text[:text.index("<details>")]
    assert "Không tìm thấy lỗ hổng nào trong code của PR" in summary
    assert "🔴" not in text and "lỗi thật" not in summary
    assert "Cảnh báo khi quét ứng dụng đang chạy (ZAP): 3" in text
    assert "có thể đã có từ trước PR" in text
    # the same rule on several routes is one row, with its fix once
    assert text.count("Thêm middleware đặt X-Frame-Options") == 2  # 10020 and 10021 rows
    assert "`GET /`, `GET /login`" in text
    assert "Báo nhầm của công cụ quét đã gỡ: 1" in text


def test_vulnerabilities_of_the_pr_come_first_and_severe_dast_stays_visible():
    tp = entry()
    agent = entry(source="agent", finding_id="agent:1", finding_ids=[], title="IDOR khi xuất")
    sqli = dast("GET /search", rule="40018", sev="HIGH")
    text = render_markdown(Report(meta=meta(), findings=[dast("GET /"), tp, agent, sqli]))
    summary = text[:text.index("### ")]
    assert "🔴 3 lỗi cần sửa" in summary and "1 do Agent tự tìm" in summary
    assert "Cảnh báo khi quét ứng dụng đang chạy (ZAP): 1" in text  # only the MEDIUM one
    main = text[:text.index("<details>")]
    assert "40018 (zap)" in main and "IDOR khi xuất" in main and "SQL ghép chuỗi" in main


def test_markdown_report_does_not_name_how_the_llm_was_reached():
    """The PR comment shows the model, not whether it ran with an API key or claude-mcp."""
    for provider in ("claude-mcp", "anthropic", "gemini"):
        text = render_markdown(Report(meta=meta(provider=provider), findings=[entry()]))
        assert provider not in text and "LLM `" not in text and "claude-sonnet-5-5" in text


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


def test_build_review_comments_on_the_vulnerable_line():
    diff = PrDiff({SERVICE: FileDiff(SERVICE, {14, 15})})
    review = build_review(Report(meta=meta(), findings=[entry()]), diff, "abc123")
    (comment,) = review["comments"]
    assert review["commit_id"] == "abc123" and review["event"] == "COMMENT"
    assert "secagent-review:abc123" in review["body"]
    assert comment == {"path": SERVICE, "line": 15, "side": "RIGHT", "body": comment["body"]}
    body = comment["body"]
    assert "SQL ghép chuỗi" in body and f"**Đề xuất sửa:** {FIX}" in body and "CWE-89" in body
    assert "```" not in body  # words only: the developer writes the code


def test_build_review_skips_lines_outside_the_pr_and_non_tp():
    outside = PrDiff({SERVICE: FileDiff(SERVICE, {30})})
    assert build_review(Report(meta=meta(), findings=[entry()]), outside, "h") is None
    inside = PrDiff({SERVICE: FileDiff(SERVICE, {15})})
    for verdict in ("FP", "NEEDS_REVIEW"):
        assert build_review(Report(meta=meta(), findings=[entry(verdict)]), inside, "h") is None
