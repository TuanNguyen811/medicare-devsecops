# Thiết kế bổ sung: chế độ LLM claude-mcp, DAST, ký image, deploy, giám sát, mở rộng benchmark

- **Ngày:** 2026-11-21
- **Bổ sung cho:** `2026-11-07-devsecops-ai-agent-design.md` (gọi tắt là *spec gốc*). Phần nào ở đây khác spec gốc thì **tài liệu này thắng**. Phần không nhắc tới giữ nguyên.
- **Trạng thái:** đã duyệt; bản hiện hành 2026-11-22.

## 0. Vì sao bổ sung

1. **`secagent` cần một LLM.** Ngoài các chế độ gọi API bằng key (`anthropic`, `openai`, `gemini`), `secagent` có thêm chế độ **`claude-mcp`**: dùng Claude Code đã đăng nhập trên máy làm LLM, không cần API key. Benchmark chạy bằng chế độ này (gói Claude Max 5x).
   - `claude-mcp` **chỉ chạy trên máy.** Thông tin đăng nhập không bao giờ đặt trên GitHub, và nội dung PR không điều khiển được một tiến trình có tài khoản của người dùng.
   - Trên CI, `secagent` dùng các chế độ có key (`LLM_API_KEY`). Chưa có key thì gate dùng chế độ truyền thống (fail-safe).
2. **Đồ án thiếu phân tích động (DAST)** và **thiếu phần Ops** (deploy thật, kiểm soát chuỗi cung ứng, giám sát). Spec gốc để DAST ngoài phạm vi. Giờ đưa vào để luồng DevSecOps khép kín như thực tế: code → PR → build → ký → deploy → giám sát.
3. **Benchmark cần nhiều kịch bản lỗi logic hơn**, vì đây là nhóm lỗi công cụ quét và DAST đều không bắt được, cũng là lý do tồn tại của AI Agent.

**Thành công là khi:**

- Một PR đi hết luồng: 6 nhóm công cụ quét + DAST → Agent (`secagent`, khi có API key; chưa có key thì gate chạy chế độ truyền thống) → comment → gate. Không cần thao tác tay.
- `main` được build, ký, gắn SBOM, rồi deploy về cụm Kubernetes trên máy bằng một lệnh. Image không có chữ ký hợp lệ bị cụm từ chối.
- Dashboard Grafana có số liệu, và cảnh báo dò mật khẩu bật lên khi chạy script giả lập.
- Benchmark chạy đủ C1, C1+DAST, C2–C5 trên khoảng 30 kịch bản. Kết quả thô và bảng tổng hợp được commit.

## 1. Mục tiêu, không làm, và những điều cấm

**Mục tiêu:** 6 phần của luồng ở mục 2.

**Không làm** (ghi vào "Hướng phát triển"): threat model riêng, chứng thực provenance SLSA, bảng đối chiếu chuẩn (SSDF/SAMM/Nghị định 13), runbook, Dependabot, Falco, Argo CD, deploy lên cloud.

**Những điều cấm** (làm vậy là hỏng dù chạy được):

- Bảng số liệu không ghi rõ chế độ LLM và model. Mọi bảng phải ghi, ví dụ `claude-mcp / claude-sonnet-5-5`.
- Deploy nhánh có lỗ hổng ra nơi truy cập được từ mạng. App, Grafana, Prometheus chỉ mở ở `127.0.0.1` (qua `kubectl port-forward`).
- Sửa `infra/k8s/` hoặc `infra/terraform/` để phục vụ deploy. Đây là đối tượng quét IaC: cảnh báo trên bản sạch là dữ liệu báo nhầm, và S10 sửa đúng các file này.
- Làm yếu nguyên tắc fail-safe của gate: agent lỗi → `agent-exit=2` → chế độ `traditional`.
- Cho LLM quyền chạy lệnh, truy cập web, hay ghi file. LLM chỉ dùng các công cụ chỉ đọc của `secagent` và các công cụ nộp kết luận.

## 2. Luồng tổng thể

```
1. MÁY LẬP TRÌNH VIÊN   pre-commit Gitleaks → push (GitHub push protection) → mở PR
2. PR (pr-security.yml) build-test | Semgrep, Bandit, CodeQL | Trivy | Gitleaks | Checkov, zizmor
                        | DAST: ZAP [MỚI]
                        → ai-security-agent (secagent, API key)
                        → agent-comment → quality-gate → review, label → merge
3. MAIN (main-ci.yml)   build-test → full-scan → image → Trivy image → SBOM
                        → cosign ký + SBOM attestation [MỚI] → GHCR → staging tạm
4. DEPLOY [MỚI]         deploy/pull-deploy.sh trên máy: cosign verify → apply overlay
                        → Kyverno kiểm tra chữ ký → rollout → smoke test (lỗi thì rollback)
                        → ZAP quét sau deploy
5. GIÁM SÁT [MỚI]       /metrics → Prometheus → Grafana; Alertmanager; script giả lập truy cập
                        nightly-sca (đã có)
6. BENCHMARK [MỞ RỘNG]  ~30 kịch bản × C1, C1+DAST, C2–C5 (claude-mcp) → evaluate → bảng, biểu đồ
```

## 3. Các phương án đã cân nhắc

| Quyết định | Phương án | Đánh đổi | Chọn |
|---|---|---|---|
| LLM cho benchmark | (a) API key; (b) **`claude-mcp`: Claude Code trên máy làm LLM của `secagent`** | (a) tốn tiền API; (b) không tốn tiền, nhưng số liệu gắn với model Claude | **(b)**, người dùng chọn |
| `claude-mcp` dùng những gì của `secagent` | (a) chỉ dùng đầu vào và đầu ra, để Claude Code tự đọc code; (b) **giữ y nguyên prompt, công cụ, các pha; chỉ thay lớp gọi LLM** | (a) không đo được kiến trúc agent (công cụ AST, Function Calling); (b) phải viết cầu MCP | **(b)**, người dùng chọn |
| `claude-mcp` chạy ở đâu | (a) cả trên CI; (b) **chỉ trên máy** | (a) thông tin đăng nhập nằm trên GitHub, và nội dung PR có thể prompt-inject tiến trình mang tài khoản; (b) CI không thêm rủi ro | **(b)**, người dùng chọn |
| Ai chạy LLM trong benchmark | (a) phiên Claude Code đang điều phối hoặc subagent của nó; (b) **tiến trình `claude -p` mới cho mỗi lượt** | (a) phiên đó viết kịch bản và đáp án, không tái lập được; (b) sạch, khóa quyền, script chạy lại được | **(b)**, mình quyết |
| Deploy về máy | (a) **script kéo về + Kyverno**; (b) Argo CD + Kyverno; (c) self-hosted runner | (b) nặng hơn ~1 GB, CI phải ghi vào repo; (c) repo public → PR từ fork chạy code trên máy | **(a)**, người dùng chọn |
| Giám sát | (a) kube-prometheus-stack; (b) **manifest Prometheus + Grafana + Alertmanager gọn** | (a) ~2 GB RAM, cần Helm | **(b)**, mình quyết |
| ZAP đọc API | (a) bật `/openapi.json`; (b) **xuất file OpenAPI lúc build, endpoint vẫn tắt** | (a) mở thêm bề mặt tấn công | **(b)**, mình quyết |
| Kết quả ZAP → SARIF | (a) template SARIF có sẵn của ZAP; (b) **bộ chuyển tự viết từ báo cáo JSON của ZAP** | (b) kiểm soát được rule id, mức độ, định danh; có test | **(b)**, mình quyết |
| ZAP đăng nhập bằng vai trò nào | (a) một vai trò; (b) **mỗi vai trò một lần quét, chạy song song** | (a) bỏ sót tính năng của vai trò khác | **(b)**, mình quyết |

## 4. Chế độ LLM của `secagent` và `claude-mcp`

### 4.1 Bốn chế độ

| `LLM_PROVIDER` | LLM | Cần | Chạy ở |
|---|---|---|---|
| `anthropic` (mặc định) | Claude qua API | `LLM_API_KEY` | CI và máy |
| `openai` | OpenAI qua API | `LLM_API_KEY` | CI và máy |
| `gemini` | Gemini qua API | `LLM_API_KEY` | CI và máy |
| `claude-mcp` | Claude Code đã đăng nhập trên máy | không cần key | **chỉ máy**; từ chối khi `--mode ci` |

Bốn chế độ dùng chung toàn bộ code của `secagent`. Chúng chỉ khác lớp gọi LLM (`secagent/llm/`). `LLM_MODEL` chọn model. Với `claude-mcp`, model mặc định là `claude-sonnet-5-5`.

### 4.2 Kiến trúc `claude-mcp`

```
secagent (y nguyên): pha 0 (SARIF, diff, che secret) → review theo lô cluster → kiểm độ phủ
                     → chống bịa → report.json, report.md, agent.sarif
   lớp LLM = claude-mcp:
     claude -p  --system-prompt <prompts/system.md>  --model <LLM_MODEL>
                --tools ""  --strict-mcp-config --mcp-config <cầu MCP>
                --allowedTools mcp__secagent  --permission-mode dontAsk
                --output-format stream-json
        │  gọi công cụ qua MCP (stdio)
        ▼
     cầu MCP (secagent.mcp_bridge): phục vụ ToolRegistry của secagent
        công cụ đọc: get_diff, read_file, search_code, list_files, list_findings, get_finding,
                     list_routes, get_function, find_callers, get_dependency_usage,
                     read_security_requirements
        công cụ nộp: submit_verdict, report_finding, finish → vào trạng thái phiên
     (trạng thái phiên nằm trong tiến trình secagent; cầu chỉ chuyển tiếp qua socket 127.0.0.1
      có token riêng của phiên)
```

- **Cùng prompt:** system prompt là `prompts/system.md`; tin nhắn đầu dựng bằng `review.md` như chế độ API.
- **Cùng công cụ:** cầu MCP phục vụ đúng các công cụ mà chế độ API đưa cho model, với cùng giới hạn đường dẫn, cùng cách che secret và cùng vỏ bọc `<untrusted-code>`. Cờ `--no-ast-tools` và `--no-requirements` bỏ công cụ tương ứng khỏi danh sách.
- **Cùng các pha:** mỗi lô cluster chạy một `claude -p`. Cluster còn thiếu kết luận được hỏi lại trong một phiên mới, chỉ gồm các cluster đó. Sau đó là chống bịa và báo cáo, bằng đúng code của secagent.
- **`--strategy single-shot`:** như chế độ API, cầu MCP chỉ có các công cụ nộp kết luận (không có công cụ đọc). Toàn bộ ngữ cảnh nằm trong prompt `single_shot.md`. Giới hạn 2 lượt, vì Claude Code tính câu trả lời kết thúc sau kết quả công cụ là một lượt riêng.
- **`meta`:** lấy từ đầu ra stream-json: model thật, số lượt gọi, token vào và ra, thời gian, chi phí quy đổi theo bảng giá API. `report.md` ghi chế độ và model ở chân báo cáo (dạng "LLM claude-mcp · model …").

### 4.3 Khóa quyền

- `--tools ""`: không có công cụ có sẵn nào của Claude Code (không đọc hay ghi file trực tiếp, không chạy lệnh, không vào web).
- `--strict-mcp-config`: chỉ nạp cầu MCP của secagent. Các công cụ của cầu chỉ đọc trong repo; `.git/` và `sarif/` bị cấm (SARIF thô chưa che secret).
- `--permission-mode dontAsk` cộng `--allowedTools mcp__secagent`: mọi thứ khác bị từ chối, không hỏi.
- **Mỗi lượt là một phiên sạch** (`--setting-sources project --disable-slash-commands --no-session-persistence`): không nạp cài đặt, hook, plugin hay MCP cá nhân, không có lịch sử hội thoại.
- **Trong benchmark:** thư mục chạy không chứa đáp án. Phiên Claude Code điều phối benchmark không chấm thay.
- Thông tin đăng nhập là của Claude Code trên máy. `secagent` không đọc, không chép và không truyền nó đi đâu.

### 4.4 Trên CI

- Job `ai-agent` của `pr-security.yml` chạy `secagent` bằng `LLM_API_KEY` với `anthropic`, `openai` hoặc `gemini`. Không có thông tin đăng nhập Claude trên GitHub.
- Mọi job checkout code PR (`ai-agent`, `quality-gate`) đều xóa `out/` trước khi dùng, vì `out/` trong code PR do người mở PR kiểm soát (chặn trường hợp PR tự đặt sẵn `out/agent-exit=0`).

### 4.5 Cấu hình

- Cờ cách ly và cách gọi nằm ở một chỗ: `agent/src/secagent/llm/claude_mcp.py`. Model chọn bằng `LLM_MODEL` (mặc định `claude-sonnet-5-5`); số lượt là giới hạn bước của phiên review; timeout là phần còn lại của ngân sách thời gian (`--time-budget-s`).
- CLI `claude` trên máy: bản đi kèm extension VS Code (`claude.exe`), hoặc cài bằng `npm install -g @anthropic-ai/claude-code`. Đường dẫn đặt qua `CLAUDE_BIN`.

## 5. DAST với OWASP ZAP

### 5.1 Thành phần (thư mục `security/dast/`)

| File | Việc |
|---|---|
| `export_openapi.py` | Import app với OpenAPI bật tạm trong tiến trình, ghi `openapi.json`. Endpoint trên app vẫn tắt. |
| `login.py --role <ROLE> --base <url>` | Lấy `csrf_token` từ trang `/login`, đăng nhập bằng tài khoản demo của vai trò, in ra cookie phiên. |
| `zap-plan.yaml` | Kế hoạch ZAP Automation Framework: context chỉ gồm `base`; cookie phiên gắn vào mọi request (replacer); khai báo `csrf_token` là anti-CSRF token; import `openapi.json`; spider; active scan với bộ rule tiêm/duyệt đường dẫn/SSTI/SSRF/XSS/lệnh; báo cáo JSON. |
| `zap2sarif.py` | Chuyển báo cáo JSON của nhiều lần quét (nhiều vai trò) thành **một** `zap.sarif`, gộp trùng theo (pluginId, method, đường dẫn mẫu). Có unit test. |
| `run-dast.sh <base-url> <out-dir> [roles]` | Gói các bước trên cho CI, deploy và benchmark. |

Phiên bản ZAP ghim bằng digest image trong `security/tool-versions.env` (`ZAP_IMAGE=ghcr.io/zaproxy/zaproxy@sha256:...`).

**Loại khỏi phạm vi quét:** `/logout`; `/account/password` (để không tự đổi mật khẩu); `POST /login` khi active scan (để không tự khóa tài khoản theo R-07).

### 5.2 Định dạng SARIF của DAST

- Tên công cụ (tên file) là `zap`. Hợp đồng 2 thêm `zap` vào danh sách `<tool>`.
- `ruleId` = pluginId của ZAP. Mức độ: risk High → `HIGH`, Medium → `MEDIUM`, Low → `LOW`, Informational → `NOTE`. Ghi vào `properties.security-severity` để gate đọc như các công cụ khác.
- Vị trí: `artifactLocation.uri = "dast:<METHOD> <đường dẫn mẫu>"`, ví dụ `dast:GET /patients/search`, `startLine` để trống. Finding id = `zap:<pluginId>:dast:<METHOD> <đường dẫn mẫu>:0`.
- `properties`: `cwe`, `roles` (các vai trò thấy lỗi), `evidence`, `param`.

### 5.3 Gate và Agent xử lý DAST

- **Gate:** finding của `zap` được miễn bộ lọc "chỉ xét file trong diff" giống nhóm commit-scoped (Gitleaks), tức là luôn được xét. Bộ lọc tương ứng trong `secagent` (đánh dấu trong diff) cũng miễn cho `zap`. Chặn theo cùng quy tắc High/Critical. Bản `main` sạch phải có 0 cảnh báo High của ZAP; nếu có thì điều tra trước khi bật.
- **Ánh xạ route → code (quyết định của mình):** pha 0 của `secagent` dùng công cụ AST `list_routes` để tìm hàm xử lý của mỗi `METHOD path` của ZAP, rồi gắn file và dòng của hàm đó vào finding làm vị trí liên quan (related location). Nhờ vậy kiểm tra chống bịa (`fp_is_anchored` trong `phases/check.py`) vẫn giữ nguyên độ chặt: kết luận FP cho finding ZAP phải trích đúng code của hàm xử lý hoặc file liên quan. Route không ánh xạ được → finding giữ nguyên; kết luận FP không neo được thì thành `NEEDS_REVIEW`. **Không** nới lỏng chống bịa kiểu Trivy.
- **Agent:** nhận finding `zap` như mọi nguồn khác, kèm vị trí liên quan ở trên.
- **DAST lỗi thì chặn (quyết định của mình):** job `dast` nằm trong danh sách job bắt buộc `success` của `quality-gate`, giống mọi công cụ quét. Lỗi gồm ZAP crash, app không lên, timeout. Mỗi lần quét của một vai trò tự thử lại 1 lần trước khi báo lỗi. Thiếu SARIF của DAST không bao giờ được hiểu là "không có phát hiện".

### 5.4 Ba chỗ chạy DAST

1. **PR** (`pr-security.yml`):
   - Job `dast-zap` dạng ma trận 5 vai trò, mỗi vai trò một runner, chạy song song với các job quét. Mỗi job: build image từ code PR, `compose up` với secret sinh tại chỗ (như job staging), seed, xuất OpenAPI, quét, upload JSON thô. **Không tham chiếu secret nào.**
   - Job `dast` gom và chạy `zap2sarif`, upload artifact `sarif-zap` và SARIF category `dast`.
   - Bỏ qua PR từ fork giống các job khác có upload SARIF.
2. **Sau deploy:** `pull-deploy.sh` chạy `run-dast.sh` vào bản vừa deploy (qua port-forward), quét đủ 5 vai trò. Báo cáo lưu ở `deploy/reports/<thời điểm>/` (không commit).
3. **Benchmark:** cấu hình C1+DAST (mục 8).

### 5.5 Mục tiêu thời gian

Spec gốc mục 3.6 (≤ 5 phút) được thay bằng: **pipeline PR ≤ 15 phút**. Ước tính:

| Chặng | Thời gian |
|---|---|
| Các job quét và DAST (song song) | khoảng 6–8 phút |
| Agent | khoảng 3–6 phút |

Thời gian thực đo và báo cáo. Đây là đánh đổi tốc độ lấy độ phủ.

## 6. Ký image và deploy về máy

### 6.1 Ký trong `main-ci.yml` (job `image`)

- Chỉ chạy khi `github.ref == refs/heads/main`. Quyền thêm: `id-token: write`.
- Sau khi push, lấy digest:
  1. `cosign sign --yes <image>@<digest>` (keyless qua OIDC của GitHub, ghi vào Rekor);
  2. `cosign attest --yes --type cyclonedx --predicate sbom.cdx.json <image>@<digest>`.
- Phiên bản cosign ghim cùng sha256 trong `tool-versions.env`, cài qua `security/install-tools.sh`.
- Image push từ nhánh khác `main` (thẻ `sha`) **không** được ký. Đây là dữ liệu demo "image chưa ký bị chặn".
- Danh tính ký dùng để kiểm tra: issuer `https://token.actions.githubusercontent.com`, identity `https://github.com/TuanNguyen811/medicare-devsecops/.github/workflows/main-ci.yml@refs/heads/main`.

### 6.2 Cụm Kubernetes trên máy

- Docker Desktop Kubernetes (dựng bằng kind, 1 node, context `docker-desktop`). Docker được cấp 6 CPU và 8 GB RAM.
- **Kyverno** cài từ manifest phát hành, phiên bản ghim. `ClusterPolicy` ở chế độ `Enforce` cho namespace `medicare`:
  1. image `ghcr.io/tuannguyen811/medicare-hms*` phải có chữ ký keyless đúng danh tính ở 6.1 **và** attestation CycloneDX;
  2. image phải tham chiếu theo digest.
- GHCR package `medicare-hms` đang public (đã kiểm tra: kéo được không cần đăng nhập), nên không cần imagePullSecret.

### 6.3 `deploy/local/` (kustomize overlay)

- `resources`: `../../infra/k8s` (namespace, deployment, service, networkpolicy) cộng các phần riêng: PostgreSQL (StatefulSet, PVC qua `local-path`, Service), NetworkPolicy cho app → db và Prometheus → app, Job seed dữ liệu demo.
- `patches`: `replicas: 1`. Overlay tự đặt image theo digest (kustomize `images:`; `pull-deploy.sh` ghi digest vào trước khi apply). Lý do: digest toàn số 0 trong `infra/k8s` sẽ bị Kyverno chặn ngay ở bước `apply`, trước khi kịp `set image`.
- NetworkPolicy của overlay mở thêm (không sửa `infra/k8s`): DNS (UDP/TCP 53 tới `kube-system`), app → db cổng 5432, Prometheus (namespace `monitoring`) → app cổng 9000. Policy chặn egress mặc định trong `infra/k8s` chặn cả DNS.
- Secret `medicare-env` và mật khẩu DB do `pull-deploy.sh` sinh lần đầu (giống job staging: `ENV=development`, `SECRET_KEY`, `DATABASE_URL`, `DEMO_PASSWORD`). Secret được lưu trong cụm, không ghi ra repo. `DEMO_PASSWORD` in ra một lần cho người dùng.
- Cần kiểm tra khi làm: kindnet của Docker Desktop có thực thi NetworkPolicy không. Nếu có, policy trong `infra/k8s` phải cho app nối được tới db.

### 6.4 `deploy/pull-deploy.sh [--ref latest|<digest>]`

Chạy trong Git Bash trên Windows (cũng chạy được trên Linux):

1. Kiểm tra công cụ (kubectl, cosign từ `deploy/.tools/`), context phải là `docker-desktop`.
2. Phân giải `:latest` → digest.
3. `cosign verify` và `cosign verify-attestation --type cyclonedx` với danh tính ở 6.1. Sai thì dừng, không đụng vào cụm.
4. Lần đầu: cài Kyverno và policy, sinh secret.
5. `kubectl apply -k deploy/local`, rồi `kubectl set image` theo digest. Kyverno kiểm tra lại.
6. `kubectl rollout status --timeout=180s`. Port-forward tạm, rồi smoke test giống job staging (`/health`, `/login`, chuyển hướng, 401 của API).
7. Smoke test lỗi → `kubectl rollout undo`, thoát mã khác 0.
8. Thành công → ghi lịch sử vào `deploy/.history` (không commit). Với cờ `--dast`: `run-dast.sh` quét bản vừa deploy.
   *(Sửa 2026-11-22: DAST sau deploy là tùy chọn, vì quét 5 vai trò lần lượt mất khoảng 25 phút, trong khi mỗi PR đã được quét trên CI trước khi merge.)*

Thêm `deploy/demo-unsigned.sh`: thử deploy một image thẻ `sha` (chưa ký) và in lỗi Kyverno trả về.

## 7. Giám sát

### 7.1 Ứng dụng

- Thêm `prometheus-client`. Metrics phục vụ ở **cổng riêng 9000**, không đi qua cổng 8000 và không mở qua compose hay port-forward của app. Builder chọn cách phục vụ phù hợp với uvicorn đang chạy một worker.
- Bộ đếm (không có PII theo R-10, `user_id` là số nội bộ):
  - `medicare_http_requests_total{method, route, status}` và histogram độ trễ `medicare_http_request_duration_seconds{route}`. `route` là mẫu đường dẫn, không phải URL thật.
  - `medicare_login_total{result="success|failure|locked"}`, `medicare_account_lockouts_total`.
  - `medicare_record_access_total{action, role, user_id}` (đặt cạnh lời gọi `log_access`).
  - `medicare_authz_denied_total{resource}` (đặt ở nơi `can_*` trả về không cho phép).

### 7.2 Hạ tầng giám sát (`deploy/monitoring/`, namespace `monitoring`)

- Prometheus, Alertmanager, Grafana: image ghim theo digest, manifest viết gọn, apply cùng `pull-deploy.sh`.
- Grafana có sẵn datasource và một dashboard "MediCare Security": tỷ lệ request theo status, đăng nhập thất bại, khóa tài khoản, truy cập bệnh án theo vai trò và người, từ chối quyền.
- Mật khẩu admin Grafana do script sinh. Tất cả truy cập qua port-forward `127.0.0.1`.

**Luật cảnh báo:**

| Cảnh báo | Điều kiện (ngưỡng ban đầu, builder chỉnh theo thử nghiệm) |
|---|---|
| `BruteForceSuspected` | > 20 lần đăng nhập thất bại trong 5 phút |
| `AccountLockout` | có tài khoản bị khóa trong 5 phút |
| `RecordAccessSpike` | một `user_id` truy cập > 30 bệnh án trong 5 phút |
| `AuthzDeniedSpike` | > 20 lần bị từ chối quyền trong 5 phút (dấu hiệu dò IDOR) |
| `HighErrorRate` | tỷ lệ 5xx > 5% trong 5 phút |
| `AppDown` | Prometheus không lấy được metrics trong 1 phút |

Mỗi luật có `annotations.description` ngắn bằng tiếng Việt. Cảnh báo hiển thị trên giao diện Alertmanager và Grafana, không gửi ra ngoài.

### 7.3 `deploy/simulate-traffic.py`

- Chỉ nhắm `127.0.0.1`.
- `--mode normal`: các vai trò đăng nhập, xem danh sách, xem bệnh án đúng quyền, đặt lịch, ở nhịp người dùng thật.
- `--mode brute-force`: dò mật khẩu một tài khoản → bật `BruteForceSuspected` và `AccountLockout`.
- `--mode idor-probe`: một bệnh nhân thử lần lượt id bệnh án của người khác → bật `AuthzDeniedSpike`.
- `--mode bulk-read` (thêm khi làm, để `RecordAccessSpike` cũng demo được): một bác sĩ mở liên tiếp mọi bệnh án mình được xem.

### 7.4 Quyết định khi làm (giai đoạn 4)

- **Bật metrics bằng cấu hình.** `METRICS_PORT` mặc định tắt. `METRICS_HOST` mặc định `127.0.0.1`. Overlay `deploy/local` đặt `9000` và `0.0.0.0`. Test và compose không mở cổng nào.
- **`authz_denied` chỉ đếm đối tượng có thật mà người dùng không được xem**, cùng với các lần bị chặn theo vai trò (`resource="role"`). Người ngoài vẫn nhận cùng một câu trả lời 404 (R-15), nhưng chỉ lần từ chối thật mới là dấu hiệu dò.
- **Khởi tạo sẵn các nhãn bằng 0** (kết quả đăng nhập, loại đối tượng). `increase()` trên một chuỗi xuất hiện giữa cửa sổ sẽ bỏ mất những lần tăng đầu: lúc thử, 30 lần sai chỉ đếm được 21.
- **Prometheus tìm pod qua Service headless `medicare-metrics` (DNS)**, không dùng service discovery của Kubernetes, nên không cần ServiceAccount hay RBAC.
- **TSDB và dữ liệu Grafana nằm trên emptyDir.** Demo cục bộ không cần giữ lịch sử.

## 8. Benchmark (thay mục 5.2, 5.4 của spec gốc; các mục khác giữ nguyên)

### 8.1 Mốc gốc mới

- Bổ sung quy tắc vào `docs/security-requirements.md` (nối tiếp R-15):
  - **R-16:** chỉ ADMIN được tạo tài khoản, đổi vai trò hay khóa tài khoản. Người dùng tự sửa hồ sơ chỉ được đổi các trường được liệt kê.
  - **R-17:** hóa đơn chỉ chuyển trạng thái theo đúng luồng cho phép. Số lượng và thành tiền phải dương, tính ở server.
  - **R-18:** token đặt lại mật khẩu ngẫu nhiên an toàn, dùng một lần, hết hạn sau 15 phút. Phản hồi không tiết lộ tài khoản có tồn tại hay không.
  - **R-19:** dữ liệu xuất ra file (CSV, Excel) phải trung hòa ký tự công thức và tuân theo R-11.
- Gắn tag **`v0.3-baseline`** sau khi xong các phần 4–7 (app đã có `/metrics`, rule đã bổ sung). `benchmark/BASE_COMMIT` trỏ vào mốc này. Mọi patch kịch bản áp lên mốc này.

### 8.2 Bộ dữ liệu

- **24 kịch bản lỗi:**
  - S01–S14 giữ như spec gốc;
  - S16–S24 mới, bảng dưới;
  - mỗi kịch bản là một tính năng nghe hợp lý.
- **S15:** tấn công chính Agent (prompt injection + SQLi thật).
- **~4 mồi nhử:** code an toàn nhưng trông giống lỗi.
- **Bản `main` sạch.**

| Mã | Tính năng mới | Lỗi cài vào | Quy tắc | CWE |
|---|---|---|---|---|
| S16 | Bệnh nhân tự đổi lịch hẹn | Đổi hoặc hủy được lịch của bệnh nhân khác | R-01, R-13 | 639 |
| S17 | Tự cập nhật hồ sơ cá nhân | Nhận cả trường `role` (mass assignment) → tự nâng quyền | R-16 | 915 |
| S18 | Đặt lịch nhanh | Bỏ ràng buộc unique, kiểm tra rồi mới ghi, không khóa → trùng lịch bác sĩ | R-13 | 362 |
| S19 | Danh sách bệnh nhân theo khoa cho y tá | Khoa lấy từ tham số client → xem được khoa khác | R-02, R-03 | 639 |
| S20 | Hóa đơn nhiều dòng | Số lượng âm; chuyển thẳng sang PAID bỏ qua bước | R-17, R-04 | 840 |
| S21 | Quên mật khẩu | Token không hết hạn, dùng lại được; thông báo khác nhau theo tài khoản | R-18 | 640, 204 |
| S22 | Xuất danh sách bệnh nhân CSV | CSV injection, lộ CCCD/BHYT đầy đủ | R-19, R-11 | 1236, 359 |
| S23 | Bác sĩ tự nhận bệnh nhân | Bác sĩ tự gán `attending_doctor_id` = mình → đọc bệnh án | R-02, ma trận | 285 |
| S24 | "Ghi nhớ đăng nhập" | Bỏ khóa sau 5 lần sai; đăng xuất không hủy phiên | R-07, R-08 | 307, 613 |

**Yêu cầu khi viết kịch bản:**

- Trang mới có link trong menu để ZAP spider tìm thấy. API mới có trong OpenAPI xuất ra.
- Lỗi được cài tự nhiên, không có comment gợi ý.
- `ground_truth.yaml` ghi thêm `routes: ["GET /..."]` cho mỗi lỗi để chấm được finding của DAST.

**Cân bằng:** khoảng 9 kịch bản dạng pattern (công cụ có báo, để đo Agent lọc báo nhầm mà không loại nhầm lỗi thật) và khoảng 15 kịch bản dạng logic.

**Nhãn dựa trên số đo:**
- Sau khi viết xong toàn bộ kịch bản, chạy C1 và C1+DAST.
- Ghi `measured_detection` vào `scenario.yaml` của từng kịch bản, theo từng lỗi: `scan_run` (lượt quét), `sast_sca` (id các lỗi C1 bắt được), `dast` (id các lỗi chỉ C1+DAST bắt được). Ghi theo lỗi vì một kịch bản có thể có lỗi bị bắt và lỗi bị sót. `evaluate.py` tự tính lại nhóm này từ kết quả quét; trường trong `scenario.yaml` là bản ghi để đọc.
- Bảng kết quả chia nhóm theo nhãn đo được, không theo nhãn dự đoán.

**Chia dev/test:**
- Khoảng 5 kịch bản làm tập dev (S01, S07, S10, S14, D1), dùng để chỉnh prompt của `secagent` (`prompts/system.md`, `review.md`, `single_shot.md`). Phần còn lại là tập test.
- `ground_truth.yaml` và prompt được chốt (commit) trước khi chạy tập test.

**Người viết kịch bản (thay quy ước tách người của Hợp đồng 3):** một người (Claude) viết toàn bộ kịch bản, đáp án và prompt, theo quyết định của người dùng. Biện pháp chống thiên vị:
1. **Thứ tự cố định:** viết tập dev → chỉnh prompt trên tập dev → **commit chốt prompt** → rồi mới viết kịch bản và đáp án tập test. Lịch sử git chứng minh thứ tự này.
2. **LLM không thấy đáp án:** `secagent` chạy trong worktree ở commit kịch bản (từ `v0.3-baseline`, không có thư mục `benchmark/`). Mỗi lượt LLM là một tiến trình `claude -p` riêng, không có lịch sử hội thoại. Phiên Claude điều phối benchmark không chấm và không trả lời thay.
3. **Không chỉnh prompt sau khi đã thấy kết quả tập test.** Nếu buộc phải sửa thì chạy lại toàn bộ tập test và ghi rõ lý do trong báo cáo.
4. Báo cáo nêu rõ hạn chế "người viết đề và người chỉnh prompt là một".

### 8.3 Cấu hình

Mọi cấu hình có AI chạy `secagent` ở chế độ `claude-mcp` (mục 4), model `claude-sonnet-5-5`. Chế độ và model được ghi vào `meta` của từng lượt.

| Mã | Gồm | Chạy ở đâu | Số lần |
|---|---|---|---|
| C1 | 6 nhóm công cụ quét, **kể cả CodeQL** | GitHub Actions (`benchmark-scan.yml`) | 1 |
| C1+DAST | C1 + ZAP 5 vai trò | GitHub Actions | 1 |
| **C2** | C1+DAST + secagent đầy đủ | Máy | 3 trên tập test, 1 trên tập dev |
| C3 | như C2, `--strategy single-shot` (gọi LLM một lần, không dùng công cụ) | Máy | 1 trên tập test |
| C4 | như C2, `--no-requirements` | Máy | 1 trên tập test |
| C5 | như C2, `--no-ast-tools` | Máy | 1 trên tập test |
| C2-api | như C2, chế độ `anthropic`, `openai` hoặc `gemini` bằng key, cùng script | GitHub hoặc máy | 3, khi có key |

**Câu hỏi nghiên cứu:**
- RQ1 (giảm báo nhầm): C1+DAST so với C2, xét trên mồi nhử, bản sạch và các finding sai.
- RQ2 (bắt thêm lỗi): C1+DAST so với C2.
- RQ3 (chi phí): thời gian và token đo thật. Tiền quy đổi theo bảng giá API của Claude, tức đúng số tiền nếu chạy chế độ `anthropic` bằng key. Với model khác, tiền chỉ là ước tính bằng số token nhân bảng giá, ghi rõ là ước tính.
- RQ4 (đóng góp từng phần): C2 so với C3 (Function Calling), C4 (ngữ cảnh nghiệp vụ), C5 (công cụ AST).
- Phụ: độ ổn định qua 3 lần chạy C2; S15 (prompt injection).

**Hạn chế ghi trong báo cáo:** số liệu là của "kiến trúc secagent + Claude Sonnet". Con số tuyệt đối phụ thuộc model; C2-api đo ảnh hưởng của model khi có key.

**CodeQL:** C1 chạy trên GitHub Actions bằng đúng các bước của `pr-security.yml` (cùng action CodeQL, cùng bộ query, cùng ZAP và plan), nên không cần CodeQL CLI trên máy. `security/scan-local.sh` vẫn dùng để thử nhanh khi viết kịch bản.

**Dùng lại kết quả:** `run.py` lưu SARIF của C1 và DAST theo commit kịch bản, và mọi cấu hình có agent dùng chung bộ SARIF đó. Kịch bản không sửa `app/` thì dùng lại DAST của bản sạch.

**Khối lượng:** khoảng 155 lượt agent:
- C2: 25×3 + 5;
- C3, C4, C5: mỗi cấu hình 25 lượt;
- cộng các lượt chỉnh prompt trên tập dev.

Chạy `--jobs 3`. `run.py` chạy tiếp được từ chỗ dừng và tự chờ khi chạm hạn mức của gói Max. Đổi model giữa chừng thì phải chạy lại toàn bộ cấu hình đó. Chi phí là chi phí quy đổi mà Claude Code tự báo, vì chạy bằng gói thuê bao.

### 8.4 Cách chạy và lưu kết quả

1. **Quét (GitHub Actions):** `benchmark-scan.yml` chạy bằng `workflow_dispatch`, dạng ma trận theo kịch bản. Workflow không có secret, quyền chỉ đọc. Mỗi kịch bản:
   - checkout `v0.3-baseline`, `git apply` patch, commit;
   - chạy các job quét giống `pr-security.yml`, và ZAP 5 vai trò khi kịch bản sửa `app/`;
   - upload `sarif-<kịch bản>`.
2. **Tải về:** `benchmark/run.py fetch --run <id>` tải artifact về `benchmark/results/<run-id>/scan/<kịch bản>/`.
3. **Chạy agent (máy):** `benchmark/run.py agent --config C2|C3|C4|C5 --set dev|test --reps N --jobs 3`. Mỗi lượt:
   - tạo worktree tạm ở commit kịch bản (không có `benchmark/`);
   - chạy `secagent --mode benchmark` (LLM `claude-mcp`);
   - ghi `report.json`, `trace.jsonl`, `timing.json` và đầu ra stream-json của các lượt `claude -p` vào `benchmark/results/<run-id>/<config>/<kịch bản>/<rep>/`.
4. **Chấm:** `benchmark/evaluate.py` sinh `summary.csv`, bảng Markdown và biểu đồ. Kết quả thô **được commit** để lưu vĩnh viễn, vì artifact của GitHub chỉ giữ tối đa 90 ngày.
5. **PR trưng bày:** khoảng 5 PR, mỗi nhóm một kịch bản tiêu biểu, chạy toàn bộ luồng trên GitHub. Comment và check được lưu cả khi PR đã đóng. Nhánh có lỗi không bao giờ được deploy. Phần AI trên PR chỉ có khi secagent có API key; chưa có key thì gate chạy chế độ truyền thống, và kết quả AI nằm ở `benchmark/results/`.

**Chấm DAST:** finding `zap` khớp đáp án nếu cùng `route` (method + đường dẫn mẫu) và cùng nhóm CWE. Các luật chấm khác giữ như spec gốc mục 5.3.

**Quy ước chấm (`benchmark/evaluate.py`, quyết định khi làm bước 2b):**
- **Đơn vị dự đoán:**
  - **C1, C1+DAST:** mỗi cụm phát hiện của công cụ quét mà quality gate xét (cùng cách gộp cụm của agent: cùng file, ±3 dòng, cùng nhóm CWE).
  - **C2–C5:** mỗi mục `TP` trong `report.json`, gồm cả cụm được thẩm định lẫn phát hiện agent tự tìm. `NEEDS_REVIEW` không bao giờ là phát hiện: cách chấm chặt tính nó là FP, cách chấm lỏng bỏ qua (spec gốc 5.3).
- **Khớp đáp án:**
  - cùng file, dòng nằm trong vùng lỗi ±3, và cùng nhóm CWE (theo `CWE_GROUPS` của agent). Với phát hiện agent tự tìm, chỉ cần **một** đoạn bằng chứng của nó khớp;
  - với phát hiện không có CWE (Checkov), khớp khi tên rule nằm trong `rules` của đáp án.
  - một lỗi có thể được chỉ ra ở vài chỗ (nguồn và sink, route thiếu kiểm tra và service, dòng phiên bản trong `uv.lock` và lời gọi hàm bị lỗi). Đáp án ghi các vị trí phụ trong `also: [{file, lines}]`; khớp vị trí nào cũng được, và mỗi lỗi vẫn chỉ tính một TP.
  - với phát hiện của agent, cũng khớp khi cùng vị trí và `violated_rule` của nó nằm trong danh sách quy tắc mà đáp án ghi là bị vi phạm (một lỗi có thể vi phạm nhiều quy tắc, ví dụ S07 vi phạm R-04 và R-17). CWE của một lỗi logic là lựa chọn mang tính diễn giải (tỷ lệ BHYT do client gửi có thể ghi CWE-602, CWE-472 hay CWE-639), còn quy tắc bị vi phạm thì đáp án liệt kê đủ. Quy ước này chốt trên tập dev, trước khi viết tập test.
- **Phát hiện SAST/IaC có sẵn trong file PR sửa** (ví dụ các finding Checkov của `infra/terraform/main.tf` khi PR thêm tài nguyên vào file đó) được tính như mọi dự đoán: không khớp đáp án thì là FP. Khác với DAST, chúng chỉ xuất hiện khi PR sửa đúng file, và người review PR thật cũng phải xem chúng; bảng kết quả ghi rõ số FP thuộc loại này để không phóng đại mức giảm FP ở RQ1.
- **Phát hiện DAST có sẵn trên bản gốc S00** (cùng rule ZAP, trên bất kỳ route nào, ví dụ thiếu header CSP) xuất hiện ở mọi kịch bản, vì ZAP quét cả app. Đây là vấn đề có thật nhưng không do PR gây ra. Chúng không tính TP hay FP, được đếm riêng. Benchmark đo những gì mỗi PR đưa vào. Khớp đáp án được xét trước, nên quy ước này không che được lỗi được cài.
- **Cấp PR:** quyết định của quality gate:
  - chế độ `traditional` cho C1 và C1+DAST;
  - chế độ `ai-assisted` với `report.json` của agent cho C2–C5.

  PR có lỗ hổng (`vuln`, `robustness`) phải bị chặn; mồi nhử và bản gốc phải được qua.
- **Lần chạy agent lỗi hoặc thiếu** vẫn có trong mẫu số: không phát hiện được gì (các lỗ hổng thành FN). Ở cấp PR, gate quay về chế độ truyền thống, như pipeline thật khi agent lỗi. Lần chạy dừng giữa chừng vì hạn mức của gói không phải là kết quả: `run.py` chờ rồi chạy lại.
- **Kết quả theo lần quét và phiên bản agent:** `results/runs/<scan>/<config>/<ID>/rep<N>/`. `timing.json` ghi hash cây `agent/` (gồm cả prompt). `evaluate.py` từ chối trộn kết quả của các phiên bản agent khác nhau.
- **SARIF gốc không commit**, vì quá lớn: riêng `semgrep.sarif` khoảng 1,2 MB mỗi kịch bản. Lần chạy workflow giữ SARIF 90 ngày. `run.py fetch` ghi những gì cần để chấm lại (`clusters.json`, `gate.json`, `gate_findings.json`, `changed.json`, `scenario.json`), và các file này được commit.
- `fetch` dựng lại commit kịch bản trên máy và dừng nếu SHA khác commit CI đã quét.

## 9. Thứ tự làm và ranh giới PR

| Giai đoạn | PR | Cần label `security-reviewed` |
|---|---|---|
| 0 | Tài liệu này + kế hoạch | Không |
| 1 | Vá `out/` trong workflow | Có (`.github/`) |
| 2 | DAST: `security/dast/`, job `dast-zap`/`dast`, gate nhận `zap` | Có |
| 3 | Ký image + `deploy/` + Kyverno | Có |
| 4 | Metrics trong app + `deploy/monitoring/` + script giả lập | Có thể không (nếu không sửa `.github/`, `security/`) |
| 5 | Benchmark: rule R-16–R-19, tag `v0.3-baseline`; chế độ `claude-mcp` và workflow quét benchmark; kịch bản, run/evaluate, chạy, kết quả | Có cho PR sửa `agent/` và `.github/` |
| 6 | Tài liệu (`docs/pipeline.md`, README), kịch bản demo | Không |

**Việc người dùng làm:**
- gắn label cho các PR cần;
- giữ Docker Desktop và Kubernetes chạy khi deploy hoặc chạy benchmark.

## 10. Để builder tự quyết

- Ngưỡng cụ thể của các luật cảnh báo và bộ rule active scan của ZAP, chỉnh theo thử nghiệm.
- Cách phục vụ metrics ở cổng 9000.
- Cấu trúc nội bộ của `run.py` và `evaluate.py`.
- Phiên bản cụ thể của ZAP, cosign, Kyverno, Prometheus, Grafana (ghim lúc làm).
- Nội dung chi tiết từng patch kịch bản, trong khuôn khổ bảng 8.2 và spec gốc.

## 11. Hạn chế bổ sung (ghi vào báo cáo)

- Số liệu benchmark là của `secagent` với model Claude Sonnet (chế độ `claude-mcp`). Con số tuyệt đối phụ thuộc model; C2-api đo ảnh hưởng của model khi có key. Ở chế độ `claude-mcp`, Claude Code là lớp truyền tin giữa model và các công cụ của `secagent`, và có thể thêm phần ngữ cảnh nền của riêng nó (mức độ được kiểm khi làm bước 2); prompt và công cụ của `secagent` vẫn được dùng nguyên vẹn.
- ZAP không thấy lỗi phân quyền giữa các vai trò, vì mỗi lần quét chỉ dùng một vai trò. Đây là giới hạn vốn có của DAST tự động và là điểm để so sánh với Agent.
- Deploy và giám sát chạy trên một cụm một node trên máy cá nhân. Tính sẵn sàng cao và lưu trữ lâu dài nằm ngoài phạm vi.
