"""report.md: the Pull Request comment (Vietnamese)."""

from __future__ import annotations

from collections import Counter

from secagent.context.redact import redact
from secagent.models import Report, ReportEntry

MARKER = "<!-- secagent-report -->"
MAX_CHARS = 60_000  # GitHub comments are limited to 65 536 characters
MAX_ROWS = 200
ICON = {"TP": "🔴", "NEEDS_REVIEW": "🟡", "FP": "🟢"}
APP_VERDICT = {"TP": "xác nhận", "NEEDS_REVIEW": "cần xem", "FP": "báo nhầm"}
DAST_PREFIX = "dast:"
SEVERE = {"HIGH", "CRITICAL"}
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _where(e: ReportEntry) -> str:
    return f"{e.file}:{e.line}" if e.file else "(không có vị trí)"


def _details(e: ReportEntry) -> str:
    facts = [x for x in (e.cwe, e.owasp and f"OWASP {e.owasp}",
                         e.violated_rule and f"vi phạm {e.violated_rule}",
                         f"độ tin cậy {e.confidence:.2f}", f"nguồn: {e.source}") if x]
    lines = [f"#### {ICON[e.verdict]} {e.verdict} · {e.severity} · {_cell(e.title)} — "
             f"`{_where(e)}`", "", " · ".join(facts), "", f"**Phân tích:** {e.reasoning}"]
    if e.exploit_scenario:
        lines += ["", f"**Kịch bản khai thác:** {e.exploit_scenario}"]
    if len(e.finding_ids) > 1:
        lines += ["", "Gộp các phát hiện: " + ", ".join(f"`{i}`" for i in e.finding_ids)]
    if e.fix is not None:
        lines += ["", f"**Đề xuất sửa:** {e.fix.description}"]
    return "\n".join(lines)


def _is_app_alert(e: ReportEntry) -> bool:
    """A non-severe finding of the scan of the running app (ZAP): usually app-wide settings
    such as security headers, often there before this PR. Severe ones stay with the PR's."""
    return e.file.startswith(DAST_PREFIX) and e.severity not in SEVERE


def _app_alerts(alerts: list[ReportEntry]) -> list[str]:
    """One row per alert kind and verdict, with the routes it was seen on."""
    groups: dict[tuple[str, str], list[ReportEntry]] = {}
    for e in alerts:
        groups.setdefault((e.title, e.verdict), []).append(e)
    rows = ["| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |",
            "|---|---|---|---|---|---|"]
    for (title, verdict), items in groups.items():
        first = items[0]
        routes = ", ".join(f"`{_cell(e.file.removeprefix(DAST_PREFIX))}`" for e in items)
        fix = first.fix.description if first.fix else ""
        rows.append(f"| {APP_VERDICT[verdict]} | {first.severity} | {_cell(title)} | {routes} | "
                    f"{_cell(first.reasoning)} | {_cell(fix)} |")
    return rows


def render_markdown(report: Report, head_sha: str | None = None) -> str:
    findings = report.findings
    alerts = [e for e in findings if _is_app_alert(e)]
    own = [e for e in findings if not _is_app_alert(e)]
    issues = sorted((e for e in own if e.verdict != "FP"),
                    key=lambda e: (e.verdict != "TP", -SEVERITY_ORDER.get(e.severity, 0)))
    fps = [e for e in own if e.verdict == "FP"]
    counts = Counter(e.verdict for e in issues)
    new = sum(1 for e in issues if e.source == "agent")
    if issues:
        found = []
        if counts["TP"]:
            found.append(f"🔴 {counts['TP']} lỗi cần sửa"
                         + (f" ({new} do Agent tự tìm, công cụ quét không báo)" if new else ""))
        if counts["NEEDS_REVIEW"]:
            found.append(f"🟡 {counts['NEEDS_REVIEW']} cần người xem")
        summary = "**Code của PR này:** " + " · ".join(found)
    else:
        summary = "✅ **Không tìm thấy lỗ hổng nào trong code của PR này.**"
    extra = []
    if fps:
        extra.append(f"🟢 {len(fps)} báo nhầm của công cụ quét đã được gỡ")
    if alerts:
        extra.append(f"ℹ️ {len(alerts)} cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo")
    if head_sha:
        extra.append(f"commit `{head_sha[:7]}`")
    parts = [MARKER, "## 🛡️ AI Security Agent", "", summary]
    if extra:
        parts += ["", " · ".join(extra)]
    parts.append("")
    if issues:
        parts += ["### 🔴 Lỗi cần sửa", "",
                  "| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |", "|---|---|---|---|---|---|"]
        parts += [f"| {ICON[e.verdict]} {e.verdict} | {e.severity} | {_cell(e.title)} | "
                  f"`{_cell(_where(e))}` | {e.source} | {e.confidence:.2f} |"
                  for e in issues[:MAX_ROWS]]
        if len(issues) > MAX_ROWS:
            parts.append(f"\n… và {len(issues) - MAX_ROWS} mục khác (xem report.json).")
    m = report.meta
    # How the LLM was reached (API key or claude-mcp) stays in report.json, not on the PR.
    head = f"model `{m.model}` · chiến lược `{m.strategy}`"
    footer = ["", "---", (
        f"<sub>{head} · {m.duration_s:.1f} s · "
        f"{m.llm_calls} lần gọi LLM · {m.tool_calls} lần gọi công cụ · {m.tokens_in} token vào /"
        f" {m.tokens_out} token ra · ≈ ${m.cost_usd:.4f} · chạm giới hạn: "
        f"{'có' if m.limit_hit else 'không'}" + (f" · lỗi: {m.error}" if m.error else "")
        + "</sub>")]

    fp_lines = [f"- **{_cell(e.title)}** — `{_where(e)}`: {e.reasoning}" for e in fps]
    details = [_details(e) for e in issues]
    alert_rows = _app_alerts(alerts) if alerts else []
    budget = MAX_CHARS - len("\n".join(parts + footer)) - 600
    body, dropped = [], 0
    if details:
        body += ["", "### Chi tiết"]
    for block in details:
        if len(block) + 2 > budget:
            dropped += 1
            continue
        body += ["", block]
        budget -= len(block) + 2
    if fps:
        shown = []
        for line in fp_lines:
            if len(line) + 1 > budget:
                dropped += 1
                continue
            shown.append(line)
            budget -= len(line) + 1
        body += ["", f"<details><summary>{ICON['FP']} Báo nhầm của công cụ quét đã gỡ: "
                     f"{len(fps)}</summary>", "", *shown, "", "</details>"]
    if alert_rows:
        shown = []
        for row in alert_rows:
            if len(row) + 1 > budget:
                dropped += 1
                continue
            shown.append(row)
            budget -= len(row) + 1
        body += ["", "<details><summary>ℹ️ Cảnh báo khi quét ứng dụng đang chạy (ZAP): "
                     f"{len(alerts)}</summary>", "",
                 "Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình "
                 "chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và "
                 "không làm PR bị chặn ở mức MEDIUM/LOW.", "", *shown, "", "</details>"]
    if dropped:
        body += ["", f"_… cắt bớt {dropped} mục do giới hạn độ dài comment; xem đầy đủ trong "
                     "report.json (artifact `agent-report`)._"]
    return redact("\n".join(parts + body + footer) + "\n")[:MAX_CHARS]


def render_failure(reason: str) -> str:
    return (f"{MARKER}\n## 🛡️ AI Security Agent\n\n⚠️ Agent lỗi ({redact(reason)}), quality gate "
            "dùng chế độ `traditional`.\n")
