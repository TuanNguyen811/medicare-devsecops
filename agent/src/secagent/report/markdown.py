"""report.md: the Pull Request comment (Vietnamese)."""

from __future__ import annotations

import re
from collections import Counter

from secagent.context.redact import redact
from secagent.models import Fix, Report, ReportEntry

MARKER = "<!-- secagent-report -->"
MAX_CHARS = 60_000  # GitHub comments are limited to 65 536 characters
MAX_ROWS = 200
ICON = {"TP": "🔴", "NEEDS_REVIEW": "🟡", "FP": "🟢"}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _where(e: ReportEntry) -> str:
    return f"{e.file}:{e.line}" if e.file else "(không có vị trí)"


def fence(text: str, lang: str = "") -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    marks = "`" * max(3, longest + 1)
    return f"{marks}{lang}\n{text.rstrip(chr(10))}\n{marks}"


def _validation(fix: Fix) -> str:
    if fix.validated is True:
        return "✅ đã kiểm chứng: áp được, test đạt, Semgrep sạch"
    if fix.validated is False:
        return f"❌ không qua kiểm chứng: {fix.validation_note or 'không rõ'}"
    return "chưa kiểm chứng" + (f" ({fix.validation_note})" if fix.validation_note else "")


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
        if e.fix.patch:
            lines += [f"Bản vá ({_validation(e.fix)}):", "", fence(e.fix.patch, "diff")]
    return "\n".join(lines)


def render_markdown(report: Report, head_sha: str | None = None) -> str:
    findings = report.findings
    counts = Counter(e.verdict for e in findings)
    new = sum(1 for e in findings if e.source == "agent")
    summary = (f"**Kết quả:** {counts['TP']} lỗi thật (TP) · {counts['NEEDS_REVIEW']} cần người "
               f"xem (NEEDS_REVIEW) · {counts['FP']} báo nhầm (FP) · trong đó {new} phát hiện "
               "mới do Agent tự tìm")
    if head_sha:
        summary += f" · commit `{head_sha[:7]}`"
    parts = [MARKER, "## 🛡️ AI Security Agent", "", summary, ""]
    if findings:
        parts += ["| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |",
                  "|---|---|---|---|---|---|"]
        parts += [f"| {ICON[e.verdict]} {e.verdict} | {e.severity} | {e.source} | "
                  f"{_cell(e.title)} | `{_cell(_where(e))}` | {e.confidence:.2f} |"
                  for e in findings[:MAX_ROWS]]
        if len(findings) > MAX_ROWS:
            parts.append(f"\n… và {len(findings) - MAX_ROWS} phát hiện khác (xem report.json).")
    else:
        parts.append("Không có phát hiện nào cần thẩm định.")
    m = report.meta
    footer = ["", "---", (
        f"<sub>Model `{m.model}` · chiến lược `{m.strategy}` · {m.duration_s:.1f} s · "
        f"{m.llm_calls} lần gọi LLM · {m.tool_calls} lần gọi công cụ · {m.tokens_in} token vào /"
        f" {m.tokens_out} token ra · ≈ ${m.cost_usd:.4f} · chạm giới hạn: "
        f"{'có' if m.limit_hit else 'không'}" + (f" · lỗi: {m.error}" if m.error else "")
        + "</sub>")]

    fps = [e for e in findings if e.verdict == "FP"]
    fp_lines = [f"- **{_cell(e.title)}** — `{_where(e)}`: {e.reasoning}" for e in fps]
    details = [_details(e) for e in findings if e.verdict != "FP"]
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
        body += ["", f"<details><summary>{ICON['FP']} Báo nhầm (FP): {len(fps)}</summary>", "",
                 *shown, "", "</details>"]
    if dropped:
        body += ["", f"_… cắt bớt {dropped} mục do giới hạn độ dài comment; xem đầy đủ trong "
                     "report.json (artifact `agent-report`)._"]
    return redact("\n".join(parts + body + footer) + "\n")[:MAX_CHARS]


def render_failure(reason: str) -> str:
    return (f"{MARKER}\n## 🛡️ AI Security Agent\n\n⚠️ Agent lỗi ({redact(reason)}), quality gate "
            "dùng chế độ `traditional`.\n")
