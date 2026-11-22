# Giai đoạn 5: Benchmark Implementation Plan

> **For agentic workers:** Native (Claude tự làm, review toàn nhánh bằng Opus ở cuối mỗi PR). Steps use checkbox (`- [ ]`) syntax.

**Goal:** đo bằng số liệu xem AI agent bổ sung được gì so với chỉ dùng công cụ quét, để trả lời RQ1–RQ4 của spec gốc (mục 5.1).

**Architecture:**
- Công cụ quét và DAST chạy trên GitHub Actions (`benchmark-scan.yml`, ma trận theo kịch bản), bằng đúng các bước của pipeline PR.
- Agent chạy trên máy: `secagent` ở chế độ LLM `claude-mcp` (Claude Code trên máy làm LLM; công cụ của secagent phục vụ qua cầu MCP).
- `benchmark/run.py` điều phối; `benchmark/evaluate.py` chấm điểm.

**Tech Stack:** GitHub Actions (CodeQL, Semgrep, Bandit, Trivy, Gitleaks, Checkov, zizmor, ZAP); Claude Code CLI 2.1.330 (`claude-sonnet-5-5`); Python 3.12 thư viện chuẩn và pydantic (đã có trong `agent/`).

**Spec:** `docs/superpowers/specs/2026-11-21-ops-dast-benchmark-design.md` mục 8 (sửa 2026-11-22), và spec gốc `2026-11-07-devsecops-ai-agent-design.md` mục 5 (RQ, luật chấm 5.3, hạn chế 5.7).

## Global Constraints

- Mọi patch kịch bản áp lên tag `v0.3-baseline` (`benchmark/BASE_COMMIT`).
- **LLM không bao giờ thấy đáp án:**
  - worktree của kịch bản không có `benchmark/`;
  - mỗi lượt là một `claude -p` sạch;
  - phiên Claude điều phối không chấm thay.
- **Thứ tự chống thiên vị:** tập dev → chỉnh prompt → **commit chốt prompt** → viết tập test và đáp án → commit đáp án → mới chạy tập test. Không sửa prompt sau khi đã thấy kết quả tập test.
- **Nhánh kịch bản có lỗi không bao giờ được deploy.** PR trưng bày chạy xong thì đóng và xóa nhánh.
- **Workflow benchmark:** chỉ `workflow_dispatch`, không secret, `permissions: contents: read` (cộng `actions: read` nếu cần), action ghim SHA, zizmor sạch.
- **Secret giả trong kịch bản** (S03, S08) phải là chuỗi giả, rõ ràng không dùng được, và không lọt vào `main` qua Gitleaks. Patch nằm dưới `benchmark/scenarios/`; nếu Gitleaks trên `main` bắt được thì xử lý bằng cách sinh chuỗi lúc áp patch, không dùng allowlist.
- Không sửa `infra/k8s/`, `infra/terraform/` trên `main`. Kịch bản S10 sửa chúng **trong patch**.
- Kết quả thô commit vào `benchmark/results/`.

## Bước 1: Mốc gốc `v0.3-baseline` (PR này)
- [x] `docs/security-requirements.md`: R-16…R-19, cập nhật ma trận phân quyền.
- [x] Spec mục 4, 8.3, 8.4: chế độ `claude-mcp`, bảng cấu hình C1…C5 và C2-api, cách trả lời RQ, C1 và DAST chạy trên Actions.
- [x] Kế hoạch E4: đánh dấu đã xong.
- [x] PR #12 đã merge; tag `v0.3-baseline` gắn lên merge commit `8d668bd` và đã push.

## Bước 2a: Chế độ `claude-mcp` (PR sửa `agent/`, cần label `security-reviewed`)
- [x] Prompt của secagent: R-01..R-19 (`system.md`, mô tả công cụ `read_security_requirements`).
- [x] Chế độ LLM: `anthropic` (mặc định), `openai`, `gemini`, `claude-mcp`.
  - `claude-mcp` không cần `LLM_API_KEY`, và từ chối khi `--mode ci` hoặc khi có `--thinking`.
  - Gỡ các file, lệnh và test không còn dùng trong `agent/`.
  - `meta.provider` được thêm vào Hợp đồng 2.
- [x] `secagent/llm/claude_mcp.py`:
  - `ToolRelay`: socket 127.0.0.1, token riêng của phiên, gọi công cụ tuần tự;
  - `ClaudeMcpRunner.run_session`: `claude -p` với cờ cách ly, cwd là thư mục tạm, prompt qua stdin;
  - `summarize`: đọc stream-json lấy số lượt, token, chi phí, model;
  - transcript chỉ lưu hội thoại và các con số tổng kết.
- [x] `secagent/mcp_bridge.py`: MCP stdio (`initialize`, `tools/list`, `tools/call`, `ping`), chỉ dùng thư viện chuẩn, chạy với `python -I`.
- [x] `phases/review.py`: `Session._execute` dùng chung cho cả chế độ API và `claude-mcp`; `_external` chạy một phiên; `force_submit` và `ask_missing` là phiên mới gồm prompt cộng chỉ dẫn bổ sung; single-shot giới hạn 2 lượt.
- [x] Test (`tests/test_claude_mcp.py`): relay cần token; cầu MCP qua stdio thật; lệnh `claude` được cách ly; transcript không có thông tin máy; phiên review qua runner giả (giới hạn bước, kiểm độ phủ, single-shot, lỗi giữ kết luận đã nộp).
- [x] Chạy thật trên một thay đổi IDOR (không có SARIF):
  - tìm ra CWE-639, vi phạm R-02, có kèm cách sửa;
  - model dùng `read_file`, `find_callers`, `report_finding`;
  - 19 giây, khoảng 0,07 USD quy đổi.
- [x] Review toàn nhánh (Opus), PR, label, merge (PR #13).

## Bước 2b: Bộ công cụ benchmark
- [x] **2b-1 (PR #14):** `benchmark/scenario.py` dựng kịch bản tất định, và `.github/workflows/benchmark-scan.yml`.
  - Có test SHA vàng; CI trên Linux khớp SHA tính trên máy Windows.
  - Cây kịch bản trung tính: bỏ tài liệu thực nghiệm, có test bảo đảm không còn chữ nào lộ đáp án.
  - Chạy thật với S00 (run `44997648299`): job quét và 5 job DAST đều đạt.
- [x] **2b-2:** `benchmark/run.py`.
  - `fetch`: tải artifact, gộp ZAP các vai trò, kiểm tra SHA, ghi `clusters.json`, `gate.json`, `gate_findings.json`.
  - `agent`: worktree tạm, `claude-mcp`, `--jobs`, chạy tiếp từ chỗ dừng, chờ khi chạm hạn mức, dừng khi lỗi đăng nhập.
- [x] **2b-2:** `benchmark/evaluate.py` chấm theo spec bổ sung §8.4 và sinh `results.md`. Có test cho phần khớp đáp án, cách chấm chặt và lỏng, loại phát hiện DAST có sẵn, và phần tổng hợp.
- [x] Chạy thật C2 trên S00:
  - 36 giây, 14 lượt gọi LLM, khoảng 0,10 USD quy đổi;
  - agent kết luận 9 cụm ZAP có sẵn là TP. Kết luận này đúng: thiếu header bảo mật là vấn đề thật. Vì vậy có quy ước loại phát hiện DAST có sẵn khỏi TP/FP.
- [x] Review toàn nhánh (Opus): 0 Critical, 7 Important, 6 Minor; đã sửa hết.
  - **Cách chấm chặt đã đúng spec 5.3:** NEEDS_REVIEW tính là FP, không tính TP.
  - **Phát hiện DAST có sẵn** nhận theo rule ZAP, bắt buộc có S00.
  - **Lần chạy lỗi hoặc thiếu** tính là FN; ở cấp PR dùng quyết định truyền thống.
  - **Bằng chứng:** khớp đáp án với bất kỳ đoạn nào.
  - **Kết quả theo lần quét và phiên bản agent.**
  - **Hạn mức của gói:** lần chạy dừng giữa chừng vì hạn mức được chạy lại.
  - **Timeout:** giết cả cây tiến trình.
  - **Log:** không chứa đường dẫn máy.
- [x] PR #14, PR #15.

## Bước 3: Tập dev và chốt prompt
- [ ] S01, S07, S10, S14, D1: patch và đáp án; áp sạch lên `v0.3-baseline`; test của app vẫn đạt (trừ khi lỗi cài vào cố ý làm hỏng test).
- [ ] Chạy `benchmark-scan` cho tập dev, rồi C2 ×1. Chỉnh prompt nếu thấy lỗi hệ thống (không chỉnh theo đáp án cụ thể).
- [ ] **Commit "chốt prompt"**, ghi hash commit này vào `benchmark/PROMPT_FREEZE`.

## Bước 4: Tập test
- [ ] S02–S06, S08, S09, S11–S13, S15–S24, D2–D4, bản sạch: patch và đáp án. Commit đáp án trước khi chạy.
- [ ] Chạy `benchmark-scan` cho toàn bộ, rồi ghi `measured_detection` vào `scenario.yaml`.

## Bước 5: Chạy agent và báo cáo
- [ ] C2 ×3, rồi C3, C4, C5 ×1 (tập test), `--jobs 3`.
- [ ] `evaluate.py` → `docs/benchmark-results.md`:
  - precision, recall, F1 theo cấu hình và theo nhóm;
  - báo nhầm trên mồi nhử và bản sạch;
  - độ ổn định qua 3 lần chạy;
  - S15;
  - thời gian, token, chi phí quy đổi;
  - hạn chế.

## Bước 6: PR trưng bày
- [ ] Khoảng 5 PR (lỗi dạng mẫu bị chặn; lỗi logic; mồi nhử; IaC; S15). Chụp kết quả vào `docs/benchmark-results.md`, rồi đóng PR và xóa nhánh.
