# Giai đoạn 5: Benchmark Implementation Plan

> **For agentic workers:** Native (Claude tự làm, review toàn nhánh bằng Opus ở cuối mỗi PR). Steps use checkbox (`- [ ]`) syntax.

**Goal:** đo bằng số liệu xem AI agent bổ sung được gì so với chỉ dùng công cụ quét, để trả lời RQ1–RQ5 của spec gốc (mục 5.1).

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
- [ ] PR, CI xanh, người dùng merge → gắn tag `v0.3-baseline` lên merge commit và push tag.

## Bước 2: Bộ công cụ benchmark (PR sửa `agent/` và `.github/`, cần label `security-reviewed`)
- [ ] Prompt của secagent: đổi R-01..R-15 → R-01..R-19 (`system.md`, mô tả công cụ `read_security_requirements`).
- [ ] Chế độ LLM: `anthropic` (mặc định), `openai`, `gemini`, `claude-mcp`.
  - `claude-mcp` không cần `LLM_API_KEY`, và từ chối chạy khi `--mode ci`.
  - Gỡ các file, lệnh và test không còn dùng trong `agent/` (liệt kê trong mô tả PR). Giữ phần đọc đầu ra stream-json để điền `meta`.
  - Cập nhật test, `agent/README.md` và đoạn regex che key.
- [ ] Cầu MCP `secagent.mcp_bridge`:
  - JSON-RPC stdio tối thiểu: `initialize`, `tools/list`, `tools/call`;
  - phục vụ `ToolRegistry` của secagent (công cụ đọc, `submit_verdict`, `report_finding`, `finish`), trạng thái phiên ghi ra file.

  Test: liệt kê công cụ khớp registry; gọi công cụ đọc; submit được ghi lại; đường dẫn ngoài repo bị từ chối.
- [ ] Lớp LLM `claude-mcp` trong `run_review`:
  - với mỗi lô: `claude -p --system-prompt … --tools "" --strict-mcp-config --mcp-config … --allowedTools mcp__secagent__*`;
  - kiểm độ phủ bằng một phiên mới;
  - `single-shot`: `--tools ""`, không MCP, đọc JSON cuối.

  Model, số lượt và timeout đặt trong `agent/claude-mcp.env`. Test bằng `claude` giả.
- [ ] `.github/workflows/benchmark-scan.yml`: ma trận kịch bản; bước quét dùng chung với `pr-security.yml` (cùng lệnh và phiên bản); ZAP khi kịch bản sửa `app/`; upload SARIF.
- [ ] `benchmark/`:
  - `BASE_COMMIT`;
  - `scenarios/<mã>/{patch.diff, scenario.yaml, ground_truth.yaml}`, có schema và kiểm tra schema;
  - `run.py` (`fetch`, `agent`, chạy tiếp từ chỗ dừng, chờ khi chạm hạn mức, `--jobs`);
  - `evaluate.py` (luật 5.3 cùng luật chấm DAST theo route, cách đếm NEEDS_REVIEW chặt và lỏng, nhóm theo `measured_detection`).

  Có test cho phần chấm điểm.
- [ ] Chạy thử thật một lượt C2 trên bản sạch. Review toàn nhánh (Opus), rồi mở PR.

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
  - bản vá;
  - thời gian, token, chi phí quy đổi;
  - hạn chế.

## Bước 6: PR trưng bày
- [ ] Khoảng 5 PR (lỗi dạng mẫu bị chặn; lỗi logic; mồi nhử; IaC; S15). Chụp kết quả vào `docs/benchmark-results.md`, rồi đóng PR và xóa nhánh.
