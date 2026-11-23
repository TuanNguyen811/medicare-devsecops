# MediCare DevSecOps

Đồ án tốt nghiệp ngành An toàn thông tin: **Xây dựng quy trình DevSecOps tích hợp AI Security Agent hỗ trợ phát hiện, thẩm định và khắc phục lỗ hổng bảo mật.**

> ⚠️ Repo này chứa các kịch bản lỗ hổng **được cài có chủ đích** phục vụ nghiên cứu. Không triển khai các nhánh kịch bản lên môi trường public. Toàn bộ dữ liệu bệnh nhân là dữ liệu giả.

## Cấu trúc repo

- `app/`: MediCare HMS, hệ thống quản lý bệnh viện mẫu (FastAPI), là ứng dụng mục tiêu
- `agent/`: AI Security Agent (Python, Function Calling; LLM là Claude, OpenAI hoặc Gemini qua API key, hoặc Claude Code trên máy qua MCP)
- `.github/workflows/`: pipeline CI/CD tích hợp SAST, SCA, Secret Scan, IaC Scan, DAST và AI Agent
- `security/`: cấu hình công cụ quét, DAST (ZAP), quality gate, chuyển report của AI lên PR
- `deploy/`: deploy kiểu pull về Kubernetes trên máy, Kyverno kiểm chữ ký image, giám sát
- `infra/`: Terraform và manifest Kubernetes mẫu (chỉ để quét), `docker-compose.yml` để chạy thật
- `benchmark/`: bộ thực nghiệm so sánh DevSecOps truyền thống và DevSecOps tích hợp AI Agent
- `docs/`: thiết kế và tài liệu

## Luồng hoạt động toàn bộ dự án

- [Phần mềm mục tiêu: MediCare HMS](#0-phần-mềm-mục-tiêu-medicare-hms)
- [Luồng chính: từ lúc viết code tới lúc chạy thật](#1-luồng-chính-từ-lúc-viết-code-tới-lúc-chạy-thật)
- [Bên trong AI Agent](#2-bên-trong-ai-agent-bước-4)
- [Ví dụ một PR cụ thể](#3-ví-dụ-một-pr-cụ-thể-demo-1-pr-20)
- [Luồng benchmark](#4-luồng-benchmark-cách-đo-hiệu-quả)
- [Tóm tắt](#5-tóm-tắt)

### 0. Phần mềm mục tiêu: MediCare HMS

```text
┌──────────────────────────────────────────────────────────────┐
│ MediCare HMS: web quản lý bệnh viện (FastAPI + PostgreSQL)   │
│ Dữ liệu giả, ~3.100 dòng Python, 264 test                    │
│                                                              │
│ 5 vai trò:                                                   │
│   Admin     : quản lý tài khoản, danh mục thuốc, audit log   │
│   Lễ tân    : tiếp nhận bệnh nhân, lịch hẹn, hóa đơn         │
│   Bác sĩ    : ghi bệnh án, kê đơn (bệnh nhân mình phụ trách) │
│   Y tá      : xem bệnh án bệnh nhân cùng khoa                │
│   Bệnh nhân : đặt lịch, xem dữ liệu của chính mình           │
│                                                              │
│ Luồng nghiệp vụ:                                             │
│   Tiếp nhận → Đặt lịch → Khám, ghi bệnh án → Kê đơn          │
│   → Hóa đơn (server tự tính BHYT) → Thu tiền                 │
│                                                              │
│ Bảo mật có sẵn: phân quyền theo vai trò và theo đối tượng,   │
│   audit log, che CCCD/BHYT, CSRF, Argon2, khóa tài khoản     │
│                                                              │
│ 19 quy tắc nghiệp vụ R-xx (security-requirements.md),        │
│   ví dụ R-01 "bệnh nhân chỉ xem dữ liệu của mình":           │
│   → AI Agent đọc để biết thế nào là sai                      │
│   → benchmark dùng làm đáp án cho lỗi logic                  │
│                                                              │
│ Nhánh main = bản SẠCH. Lỗ hổng chỉ xuất hiện qua PR          │
│ tính năng mới → đó là lúc pipeline vào cuộc                  │
└──────────────────────────────────────────────────────────────┘
```

Quy tắc nghiệp vụ: [`docs/security-requirements.md`](docs/security-requirements.md). Chạy ứng dụng: [`app/README.md`](app/README.md).

### 1. Luồng chính: từ lúc viết code tới lúc chạy thật

```text
┌──────────────────────────────────────────────────────────────┐
│ [1] LẬP TRÌNH VIÊN viết tính năng mới trên nhánh feature/*   │
└───────────────────────────────┬──────────────────────────────┘
                                │ git commit
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ [2] PRE-COMMIT (chạy trên máy lập trình viên)                │
│     • Gitleaks: có secret (mật khẩu, key) → không cho commit │
│     • Ruff: kiểm tra lint                                    │
└───────────────────────────────┬──────────────────────────────┘
                                │ git push + mở Pull Request
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ [3] CÁC CÔNG CỤ QUÉT CHẠY SONG SONG (pr-security.yml)        │
│                                                              │
│     CodeQL ──┐                                               │
│     Semgrep ─┼─ SAST: lỗi trong mã nguồn                     │
│     Bandit ──┘                                               │
│     Trivy ────── SCA: thư viện có CVE                        │
│     Gitleaks ─── secret lọt trong các commit của PR          │
│     Checkov ──── IaC: Terraform, Kubernetes, Dockerfile      │
│     zizmor ───── lỗi bảo mật trong chính file workflow       │
│     ZAP ──────── DAST: chạy app, tấn công thử với 5 vai trò  │
│                                                              │
│     build-test (pytest) chạy song song                       │
│     Kết quả: mỗi công cụ một file SARIF                      │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ [4] AI SECURITY AGENT (secagent)        chi tiết ở mục 2     │
│     Đầu vào: diff của PR + các file SARIF + mã nguồn         │
│              + quy tắc nghiệp vụ R-xx                        │
│     Đầu ra:  mỗi phát hiện kết luận TP / FP / NEEDS_REVIEW,  │
│              lỗi mới tự tìm thêm, cách sửa mô tả bằng lời    │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ [5] COMMENT LÊN PR (agent-comment)                           │
│     • Báo cáo tổng hợp: lỗi của PR, cảnh báo chung của app   │
│     • Comment ngay tại dòng lỗi: vấn đề + cách sửa           │
│     • SARIF của AI đưa lên tab Security của GitHub           │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ [6] QUALITY GATE (chế độ ai-assisted)                        │
│                                                              │
│     CHẶN khi có một trong các trường hợp:                    │
│     • AI xác nhận cảnh báo HIGH/CRITICAL là lỗi thật         │
│     • AI chưa chắc (NEEDS_REVIEW) hoặc chưa thẩm định        │
│     • AI tự tìm ra lỗi HIGH/CRITICAL, độ tin cậy ≥ 0,7       │
│                                                              │
│     An toàn khi có sự cố:                                    │
│     • Agent lỗi → quay về chế độ traditional                 │
│       (có cảnh báo HIGH là chặn)                             │
│     • Cảnh báo CRITICAL của công cụ chỉ được bỏ qua khi      │
│       người review gắn label security-reviewed               │
└───────────────┬───────────────────────────────┬──────────────┘
                │ CHẶN                          │ CHO QUA
                ▼                               ▼
   Lập trình viên sửa code            Branch protection cho phép
   theo gợi ý, push lại               merge vào main
   → quay về bước [3]
                                                │
                                                ▼
┌──────────────────────────────────────────────────────────────┐
│ [7] MAIN CI (main-ci.yml)                                    │
│     build-test → quét toàn bộ repo → docker build            │
│     → Trivy quét image (có CRITICAL thì dừng)                │
│     → tạo SBOM                                               │
│     → cosign ký image và gắn SBOM attestation                │
│     → đẩy image lên GHCR                                     │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ [8] DEPLOY KIỂU PULL (pull-deploy.sh, Kubernetes trên máy)   │
│     Máy chủ tự kéo image mới về                              │
│     → Kyverno kiểm tra chữ ký:                               │
│         image chưa ký, hoặc do nhánh khác ký → TỪ CHỐI       │
│     → triển khai lên cụm                                     │
│     → (tùy chọn --dast) ZAP quét DAST bản vừa deploy         │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ [9] GIÁM SÁT                                                 │
│     App xuất metrics → Prometheus → Grafana (dashboard)      │
│                                 └→ Alertmanager (cảnh báo)   │
│     Ví dụ: dò mật khẩu (nhiều lần đăng nhập sai)             │
│            → cảnh báo bật                                    │
└──────────────────────────────────────────────────────────────┘

Hằng đêm (nightly-sca.yml): Trivy quét lại thư viện để bắt CVE mới công bố,
kể cả khi code không đổi.
```

Chi tiết: [`docs/pipeline.md`](docs/pipeline.md) (pipeline), [`deploy/README.md`](deploy/README.md) (deploy và giám sát).

### 2. Bên trong AI Agent (bước [4])

```text
  Các file SARIF ────────────┐
  Diff của PR ───────────────┤
  Quy tắc R-xx ──────────────┘
                             ▼
┌────────────────────────────────────────────────────────┐
│ PHA 0: TIỀN XỬ LÝ                     (không dùng LLM) │
│   Chuẩn hóa cảnh báo của mọi công cụ về một dạng       │
│   → gộp trùng (cùng file, lệch ±3 dòng, cùng CWE)      │
│   → đánh dấu cảnh báo do PR tạo ra, hay đã có sẵn      │
│   → che secret trước khi gửi cho LLM                   │
└────────────────────────────┬───────────────────────────┘
                             ▼
┌────────────────────────────────────────────────────────┐
│ PHA 1: PHIÊN REVIEW                        (dùng LLM)  │
│                                                        │
│   LLM ⇄ 11 công cụ CHỈ ĐỌC:                            │
│     đọc code, tìm kiếm, liệt kê route,                 │
│     lấy thân hàm, tìm nơi gọi hàm (AST),               │
│     xem thư viện được dùng ở đâu,                      │
│     đọc quy tắc nghiệp vụ...                           │
│                                                        │
│   (a) Thẩm định từng cảnh báo: TP / FP / NEEDS_REVIEW, │
│       kèm lý do và bằng chứng                          │
│   (b) Tìm thêm: IDOR, phân quyền, lỗi logic            │
│   (c) Mô tả cách sửa bằng lời                          │
└────────────────────────────┬───────────────────────────┘
                             ▼
┌────────────────────────────────────────────────────────┐
│ PHA 2: KIỂM TRA                       (không dùng LLM) │
│   • Chống bịa: đoạn code AI trích không có thật        │
│     → hạ xuống NEEDS_REVIEW                            │
│   • Độ phủ: cảnh báo AI quên → hỏi lại một lần,        │
│     vẫn thiếu → NEEDS_REVIEW                           │
│   • Đúng định dạng (kiểm bằng Pydantic)                │
└────────────────────────────┬───────────────────────────┘
                             ▼
┌────────────────────────────────────────────────────────┐
│ PHA 3: BÁO CÁO                        (không dùng LLM) │
│   report.json, comment Markdown,                       │
│   comment tại dòng lỗi, SARIF                          │
└────────────────────────────────────────────────────────┘
```

**Chọn LLM bằng `LLM_PROVIDER`:**

```text
anthropic / openai / gemini → gọi API bằng key, chạy được ngay trên CI

claude-mcp (đang dùng) → Claude Code đã đăng nhập trên máy, qua cầu MCP:

   Pipeline chờ ──► người review chạy local_review.py trên máy
                    → secagent review PR
                    → đăng report thành comment trên PR
   Pipeline ◄────── chỉ nhận comment đúng tài khoản, đúng commit,
                    chưa bị sửa
```

Chi tiết: [`agent/README.md`](agent/README.md).

### 3. Ví dụ một PR cụ thể: [Demo 1], PR #20

```text
Lập trình viên thêm trang "tự sửa hồ sơ cá nhân"
  │  code nhận mọi trường từ form, kể cả trường role
  ▼
Công cụ quét: không cảnh báo gì (lỗi logic, không theo mẫu nào)
  ▼
AI: đọc route → đọc schema → đối chiếu quy tắc R-16
  → "Mass assignment: người dùng tự nâng quyền thành ADMIN" (CRITICAL)
  → cách sửa: chỉ nhận họ tên và số điện thoại từ form
  ▼
Gate: CHẶN, không merge được
```

Các PR trưng bày khác (để mở, không merge):

| PR | Nội dung | Kết quả |
|---|---|---|
| [#20](https://github.com/TuanNguyen811/medicare-devsecops/pull/20) | Tự sửa hồ sơ cá nhân (lỗi logic) | Chặn; AI bắt mass assignment |
| [#22](https://github.com/TuanNguyen811/medicare-devsecops/pull/22) | Nhập dữ liệu từ HIS cũ (lỗi dạng mẫu) | Chặn; AI bắt thêm XXE |
| [#23](https://github.com/TuanNguyen811/medicare-devsecops/pull/23) | Mồi nhử: code trông giống XSS nhưng an toàn | Cho qua; AI gỡ báo nhầm |
| [#24](https://github.com/TuanNguyen811/medicare-devsecops/pull/24) | IaC: sao lưu CSDL lên S3 | Chặn |
| [#25](https://github.com/TuanNguyen811/medicare-devsecops/pull/25) | Prompt injection: chú thích dụ AI bỏ qua lỗi SQL injection | Chặn |

### 4. Luồng benchmark: cách đo hiệu quả

```text
┌──────────────────────────────────────────────────────────────┐
│ CHUẨN BỊ (chống thiên vị)                                    │
│   Tập dev (5 kịch bản) → chỉnh prompt → CHỐT prompt          │
│   (PROMPT_FREEZE)                                            │
│   → viết 30 kịch bản test                                    │
│   → commit đáp án trước khi chạy                             │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ CHẠY (pr_bench.py run)                                       │
│   Với mỗi kịch bản:                                          │
│   áp patch lên main → mở PR thật "[Bench] …"                 │
│   → pipeline thật chạy (bước [3] → [6])                      │
│   → AI chạy MỘT lần, chỉ thấy code, không thấy đáp án        │
│   → thu SARIF, report của AI, quyết định thật của gate       │
│   Tổng cộng: 35 PR (#47–#81)                                 │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ CHẤM (evaluate.py, so với đáp án)                            │
│   Cùng một PR, chấm 3 cấu hình:                              │
│     C1      = chỉ công cụ quét tĩnh, gate traditional        │
│     C1+DAST = C1 + ZAP                                       │
│     C2      = C1+DAST + AI, gate ai-assisted                 │
└───────────────────────────────┬──────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────┐
│ KẾT QUẢ (tập test: 30 PR, 28 lỗ hổng)                        │
│                                                              │
│               Phát hiện  Precision  Chặn PR lỗi  Qua PR sạch │
│ Chỉ công cụ        9/28       0,43        10/20         9/10 │
│ Công cụ + AI      26/28       0,84        19/20         9/10 │
│                                                              │
│   • Lỗ hổng logic: công cụ 0/16, AI 14/16                    │
│   • 46 giây và khoảng 0,16 USD mỗi PR                        │
│   • Chống được prompt injection (S15)                        │
│   • Gate thật khớp với kết quả chấm lại ở 35/35 PR           │
│   • DAST (ZAP) không bắt thêm lỗ hổng nào                    │
│     với cấu hình hiện tại                                    │
└──────────────────────────────────────────────────────────────┘
```

**Hạn chế:**
- Một người viết cả đề, đáp án và prompt.
- Mẫu nhỏ, mỗi PR chỉ chạy một lần.
- Quy tắc của gate được sửa sau khi xem dữ liệu chạy thử.
- 6 PR sạch (D05–D10) được viết sau khi đã có kết quả.
- Số liệu phụ thuộc model (Claude Sonnet 5.5).
- Lỗ hổng mức MEDIUM không chặn PR.

Báo cáo đầy đủ và kết quả từng PR: [`docs/benchmark-results.md`](docs/benchmark-results.md).

### 5. Tóm tắt

```text
MediCare HMS (bản sạch) ─► PR tính năng mới ─► Công cụ quét
   ─► AI Agent thẩm định và tìm thêm lỗi ─► Quality gate chặn hoặc cho qua
   ─► Merge ─► Ký image ─► Deploy có kiểm chữ ký ─► Giám sát

Benchmark 35 PR thật: AI tăng phát hiện từ 9/28 lên 26/28
và precision từ 0,43 lên 0,84
```

## Tài liệu thiết kế

- Thiết kế (toàn bộ dự án): [`docs/superpowers/specs/2026-11-07-devsecops-ai-agent-design.md`](docs/superpowers/specs/2026-11-07-devsecops-ai-agent-design.md)

## Cho lập trình viên

- Chạy ứng dụng và test: xem [`app/README.md`](app/README.md).
- Bật kiểm tra trước khi commit (chặn secret bằng Gitleaks, lint bằng Ruff):

  ```bash
  uv tool install pre-commit
  pre-commit install
  ```

- Pipeline bảo mật trên GitHub Actions: xem [`docs/pipeline.md`](docs/pipeline.md).
