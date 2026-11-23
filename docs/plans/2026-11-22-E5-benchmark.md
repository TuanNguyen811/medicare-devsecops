# Giai đoạn 5: Benchmark Implementation Plan

**Goal:** đo bằng số liệu xem AI agent bổ sung được gì so với chỉ dùng công cụ quét, để trả lời RQ1–RQ3 của spec (mục 8.1).

**Architecture:**
- Mỗi kịch bản là một PR thật `[Bench] <ID> · <commit message>` vào `main`, đi qua đúng pipeline PR (`pr-security.yml`): công cụ quét, ZAP 5 vai trò, `ai-security-agent`, `agent-comment`, `quality-gate` ở chế độ `ai-assisted`.
- Agent chạy trên máy người review: `secagent` ở chế độ LLM `claude-mcp` (Claude Code trên máy làm LLM; công cụ của secagent phục vụ qua cầu MCP), một lượt cho mỗi PR, qua `security/handoff/local_review.py --benchmark-view`. Report đến job `ai-security-agent` qua comment trên PR.
- `benchmark/pr_bench.py` mở PR, gọi review và thu kết quả; `benchmark/evaluate.py` chấm điểm.

**Tech Stack:** GitHub Actions (CodeQL, Semgrep, Bandit, Trivy, Gitleaks, Checkov, zizmor, ZAP); Claude Code CLI 2.1.330 (`claude-sonnet-5-5`); `gh` CLI; Python 3.12 thư viện chuẩn, pydantic (đã có trong `agent/`) và PyYAML.

**Spec:** `docs/specs/2026-11-07-devsecops-ai-agent-design.md` mục 8 (RQ 8.1, chấm điểm 8.6, chống thiên vị 8.8) và mục 9 (hạn chế).

## Global Constraints

- Patch kịch bản viết trên tag `v0.3-baseline` (`benchmark/BASE_COMMIT`) và áp được lên `main` để mở PR.
- **LLM không bao giờ thấy đáp án:**
  - agent chỉ thấy cây `scenario.materialize` (commit gốc làm trung tính + thay đổi của PR; không có `benchmark/`, kết quả hay tài liệu thiết kế);
  - mỗi lượt là một `claude -p` sạch;
  - phiên Claude điều phối không chấm thay.
- **Thứ tự chống thiên vị:** tập dev → chỉnh prompt → **commit chốt prompt** → viết tập test và đáp án → commit đáp án → mới chạy tập test. Không sửa prompt sau khi đã thấy kết quả tập test.
- **Nhánh kịch bản có lỗi không bao giờ được deploy.** PR `[Bench]` và PR trưng bày giữ mở, không merge.
- **Secret giả trong kịch bản** (S03, S08) viết dạng `@@FAKE:<kind>:<label>@@` trong patch và được sinh lúc áp patch, nên không có chuỗi giống secret nào được commit; không dùng allowlist Gitleaks.
- Không sửa `infra/k8s/`, `infra/terraform/` trên `main`. Kịch bản S10 sửa chúng **trong patch**.
- Kết quả thô (trừ SARIF gốc) commit vào `benchmark/results/`.

## Bước 1: Mốc gốc `v0.3-baseline`
- [x] `docs/security-requirements.md`: R-16…R-19, cập nhật ma trận phân quyền.
- [x] Spec mục 5.5 và 8: chế độ `claude-mcp`, cấu hình C1, C1+DAST, C2, cách trả lời RQ.
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
- [x] `benchmark/scenario.py`: nạp kịch bản và `materialize` dựng tất định cây agent được thấy.
  - Có test SHA vàng; CI trên Linux khớp SHA tính trên máy Windows.
  - Cây kịch bản trung tính: bỏ tài liệu thực nghiệm, có test bảo đảm không còn chữ nào lộ đáp án.
- [x] `benchmark/common.py` `scan_views`: từ SARIF của một PR, dựng những gì gate và agent thấy (`clusters.json`, `gate.json`, `gate_findings.json`, `changed.json`).
- [x] `benchmark/evaluate.py` chấm theo spec mục 8.6 và sinh `results.md`, `summary.json`, `rows.json`. Có test cho phần khớp đáp án, cách chấm chặt và lỏng, loại phát hiện DAST có sẵn, và phần tổng hợp.
- [x] Chạy thử C2 trên S00: agent kết luận 9 cụm ZAP có sẵn là TP. Kết luận này đúng: thiếu header bảo mật là vấn đề thật. Vì vậy có quy ước loại phát hiện DAST có sẵn khỏi TP/FP.
- [x] Review toàn nhánh (Opus); đã sửa hết:
  - **Cách chấm chặt đúng spec mục 8.6:** NEEDS_REVIEW tính là FP, không tính TP.
  - **Phát hiện DAST có sẵn** nhận theo rule ZAP, bắt buộc có S00.
  - **Lần chạy lỗi hoặc thiếu** tính là FN; ở cấp PR dùng quyết định truyền thống.
  - **Bằng chứng:** khớp đáp án với bất kỳ đoạn nào.
  - **Kết quả theo phiên bản agent.**
  - **Hạn mức của gói:** lần chạy dừng giữa chừng vì hạn mức được chạy lại.
  - **Timeout:** giết cả cây tiến trình.
  - **Log:** không chứa đường dẫn máy.

## Bước 3: Tập dev và chốt prompt
- [x] S01, S07, S10, S14, D01: patch và đáp án; áp sạch lên `v0.3-baseline`; test của app vẫn đạt (trừ khi lỗi cài vào cố ý làm hỏng test).
- [x] Chạy C2 trên tập dev. Chỉnh prompt khi thấy lỗi hệ thống (không chỉnh theo đáp án cụ thể).
- [x] **Commit "chốt prompt"**: `benchmark/PROMPT_FREEZE` ghi cây prompt `c33491a`, chốt ở commit `16f2ec2`.

## Bước 4: Tập test
- [x] S02–S06, S08, S09, S11–S13, S15–S24 (20 PR có lỗ hổng, 28 lỗi), D02–D04 (mồi nhử), S00 (PR rỗng): patch và đáp án, review độc lập từng kịch bản. Commit đáp án trước khi chạy.
- [x] D05–D10: PR tính năng sạch thông thường. D05 viết sau khi đã biết những kết quả đầu tiên; D06–D10 viết sau khi có kết quả của 30 PR đầu, để có thêm PR sạch như trong thực tế. Đáp án commit trước khi chạy. Báo cáo ghi rõ điều này là đe dọa tính hợp lệ.

## Bước 5: Chạy benchmark bằng PR thật
- [x] `security/handoff/local_review.py --benchmark-view`: tải SARIF của lượt chạy, checkout PR, cho agent thấy đúng cây `scenario.materialize`, chạy secagent và đăng report lên PR (`security/handoff/handoff.py`: job `ai-security-agent` chỉ nhận comment chưa sửa của `AGENT_REPORT_AUTHOR` cho đúng commit HEAD). Đã kiểm tra cây agent thấy trùng khớp với `scenario.materialize` cho mọi kịch bản.
- [x] `benchmark/pr_bench.py run --tag <T>`:
  - mở PR `[Bench] <ID> · <commit message>` kế tiếp khi GitHub Actions còn dưới 30 job đang chờ hoặc đang chạy;
  - khi job `ai-security-agent` của PR chạy thì gọi review, thử lại khi chạm hạn mức hoặc lỗi tạm thời;
  - khi lượt chạy xong thì thu SARIF, `scan_views`, quyết định thật của pipeline (`pipeline.json`) và đầu ra agent; chạy tiếp được từ chỗ dừng.
- [x] Chạy `--tag r1`: 35 PR `[Bench]` (#47–#81), mỗi PR một lượt agent; kết quả ở `benchmark/results/scans/pr-r1/` và `benchmark/results/runs/pr-r1/C2/`.
- [x] `evaluate.py --scan pr-r1 --select test` và `--select dev` → `benchmark/results/summary/pr-r1-test/`, `pr-r1-dev/`; quyết định gate tính lại được đối chiếu với quyết định thật của pipeline trên từng PR.
- [x] Báo cáo `docs/benchmark-results.md`:
  - precision, recall, F1 của C1, C1+DAST, C2 (chặt và lỏng), theo nhóm pattern/logic và nhóm đo được;
  - quyết định gate cấp PR; báo nhầm trên mồi nhử, PR sạch và bản gốc;
  - S15;
  - thời gian, token, chi phí quy đổi mỗi PR;
  - tập dev báo cáo riêng;
  - hạn chế và đe dọa tính hợp lệ.

## Bước 6: PR trưng bày
- [x] 5 PR `[Demo 1]`–`[Demo 5]` (#20, #22–#25): lỗi logic (tự sửa hồ sơ); lỗi dạng mẫu bị chặn (nhập dữ liệu cũ); mồi nhử (thông báo trang chủ); IaC (sao lưu lên S3); S15 (thống kê lịch hẹn). Chạy toàn bộ luồng trên GitHub, giữ mở để trình bày cùng 35 PR `[Bench]`.
