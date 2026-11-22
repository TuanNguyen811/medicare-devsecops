# Thiết kế bổ sung: engine claude-code, DAST, ký image, deploy, giám sát, mở rộng benchmark

- **Ngày:** 2026-11-21
- **Bổ sung cho:** `2026-11-07-devsecops-ai-agent-design.md` (gọi tắt là *spec gốc*). Phần nào ở đây khác spec gốc thì **tài liệu này thắng**. Phần không nhắc tới giữ nguyên.
- **Trạng thái:** đã duyệt 2026-11-21; sửa 2026-11-22 (engine `claude-code` chỉ chạy trên máy, không chạy trên CI).

## 0. Vì sao bổ sung

1. **Chưa có API key LLM**, nên `secagent` chưa chạy được và chưa có số liệu. Nhóm có gói Claude (Max 5x). Benchmark dùng Claude Code **chạy trên máy** làm engine suy luận thay thế (cấu hình C6), đặt trong khung `secagent`, cùng đầu vào và đầu ra. Khi có key, `secagent` chạy trên cùng bộ dữ liệu (C2).
   - **CI không dùng engine này** (quyết định 2026-11-22): không đặt token Claude trên GitHub, và không để nội dung PR (có thể chứa prompt injection) điều khiển một coding agent ngay trong pipeline.
   - CI vẫn chỉ chạy `secagent` bằng `LLM_API_KEY`. Chưa có key thì gate dùng chế độ truyền thống (fail-safe).
2. **Đồ án thiếu phân tích động (DAST)** và **thiếu phần Ops** (deploy thật, kiểm soát chuỗi cung ứng, giám sát). Spec gốc để DAST ngoài phạm vi. Giờ đưa vào để luồng DevSecOps khép kín như thực tế: code → PR → build → ký → deploy → giám sát.
3. **Benchmark cần nhiều kịch bản lỗi logic hơn**, vì đây là nhóm lỗi công cụ quét và DAST đều không bắt được, cũng là lý do tồn tại của AI Agent.

**Thành công là khi:**

- Một PR đi hết luồng: 6 nhóm công cụ quét + DAST → Agent (`secagent`, khi có API key; chưa có key thì gate chạy chế độ truyền thống) → kiểm chứng bản vá → comment → gate. Không cần thao tác tay.
- `main` được build, ký, gắn SBOM, rồi deploy về cụm Kubernetes trên máy bằng một lệnh. Image không có chữ ký hợp lệ bị cụm từ chối.
- Dashboard Grafana có số liệu, và cảnh báo dò mật khẩu bật lên khi chạy script giả lập.
- Benchmark chạy đủ C1, C1+DAST, C6 trên khoảng 30 kịch bản. Kết quả thô và bảng tổng hợp được commit.

## 1. Mục tiêu, không làm, và những điều cấm

**Mục tiêu:** 6 phần của luồng ở mục 2.

**Không làm** (ghi vào "Hướng phát triển"): threat model riêng, chứng thực provenance SLSA, bảng đối chiếu chuẩn (SSDF/SAMM/Nghị định 13), runbook, Dependabot, Falco, Argo CD, deploy lên cloud.

**Những điều cấm** (làm vậy là hỏng dù chạy được):

- Trình bày kết quả của engine `claude-code` như kết quả của `secagent`. Mọi bảng số liệu ghi rõ engine và model.
- Deploy nhánh có lỗ hổng ra nơi truy cập được từ mạng. App, Grafana, Prometheus chỉ mở ở `127.0.0.1` (qua `kubectl port-forward`).
- Sửa `infra/k8s/` hoặc `infra/terraform/` để phục vụ deploy. Đây là đối tượng quét IaC: cảnh báo trên bản sạch là dữ liệu báo nhầm, và S10 sửa đúng các file này.
- Làm yếu nguyên tắc fail-safe của gate: engine lỗi → `agent-exit=2` → chế độ `traditional`.
- Cho engine suy luận quyền chạy lệnh, truy cập web, hay ghi ngoài file kết quả của nó.

## 2. Luồng tổng thể

```
1. MÁY LẬP TRÌNH VIÊN   pre-commit Gitleaks → push (GitHub push protection) → mở PR
2. PR (pr-security.yml) build-test | Semgrep, Bandit, CodeQL | Trivy | Gitleaks | Checkov, zizmor
                        | DAST: ZAP [MỚI]
                        → ai-security-agent (secagent, API key)
                        → validate-patches → agent-comment → quality-gate → review, label → merge
3. MAIN (main-ci.yml)   build-test → full-scan → image → Trivy image → SBOM
                        → cosign ký + SBOM attestation [MỚI] → GHCR → staging tạm
4. DEPLOY [MỚI]         deploy/pull-deploy.sh trên máy: cosign verify → apply overlay
                        → Kyverno kiểm tra chữ ký → rollout → smoke test (lỗi thì rollback)
                        → ZAP quét sau deploy
5. GIÁM SÁT [MỚI]       /metrics → Prometheus → Grafana; Alertmanager; script giả lập truy cập
                        nightly-sca (đã có)
6. BENCHMARK [MỞ RỘNG]  ~30 kịch bản × C1, C1+DAST, C6 → evaluate → bảng, biểu đồ
```

## 3. Các phương án đã cân nhắc

| Quyết định | Phương án | Đánh đổi | Chọn |
|---|---|---|---|
| Engine claude-code so với `secagent` | (a) review tự do, chỉ comment; (b) **cùng đầu vào và đầu ra như `secagent`** | (a) không so sánh công bằng với C2; (b) phải ép đầu ra đúng schema | **(b)**, người dùng chọn |
| Engine claude-code chạy ở đâu | (a) trên CI qua claude-code-action; (b) **chỉ trên máy, cho benchmark** | (a) token Claude nằm trên GitHub, PR có thể prompt-inject một coding agent trong pipeline; (b) CI không thêm rủi ro | **(b)**, người dùng chọn 2026-11-22 (ban đầu là (a), đã làm rồi gỡ) |
| Ai chấm benchmark C6 | (a) phiên Claude Code đang điều phối hoặc subagent của nó; (b) **tiến trình `claude -p` mới cho mỗi lượt** | (a) phiên đó viết kịch bản và đáp án, subagent thừa hưởng cài đặt, bộ nhớ, công cụ ghi; không tái lập được; (b) sạch, khóa quyền, script chạy lại được | **(b)**, mình quyết |
| Cách engine claude-code dùng code của `secagent` | (a) claude-code tự làm mọi pha; (b) **`secagent` lo tiền xử lý và hậu kiểm, claude-code chỉ lo pha suy luận** | (a) finding id lệch với gate, mất chống bịa và kiểm tra độ phủ; (b) tái dùng code đã test | **(b)**, mình quyết |
| Deploy về máy | (a) **script kéo về + Kyverno**; (b) Argo CD + Kyverno; (c) self-hosted runner | (b) nặng hơn ~1 GB, CI phải ghi vào repo; (c) repo public → PR từ fork chạy code trên máy | **(a)**, người dùng chọn |
| Giám sát | (a) kube-prometheus-stack; (b) **manifest Prometheus + Grafana + Alertmanager gọn** | (a) ~2 GB RAM, cần Helm | **(b)**, mình quyết |
| ZAP đọc API | (a) bật `/openapi.json`; (b) **xuất file OpenAPI lúc build, endpoint vẫn tắt** | (a) mở thêm bề mặt tấn công | **(b)**, mình quyết |
| Kết quả ZAP → SARIF | (a) template SARIF có sẵn của ZAP; (b) **bộ chuyển tự viết từ báo cáo JSON của ZAP** | (b) kiểm soát được rule id, mức độ, định danh; có test | **(b)**, mình quyết |
| ZAP đăng nhập bằng vai trò nào | (a) một vai trò; (b) **mỗi vai trò một lần quét, chạy song song** | (a) bỏ sót tính năng của vai trò khác | **(b)**, mình quyết |

## 4. Engine `claude-code`

### 4.1 Kiến trúc

`secagent` được tách thành 3 bước. Engine chỉ thay bước giữa:

```
secagent-prepare (không LLM)    →  ENGINE suy luận                       →  secagent-finalize (không LLM)
pha 0 của spec gốc:                  secagent:    vòng lặp function calling     pha 2 + 3 của spec gốc:
 đọc SARIF, chuẩn hóa, gộp trùng,    claude-code: `claude -p` trên máy          độ phủ, chống bịa, schema
 tính finding id, che secret,                     (chỉ benchmark, không CI)      → report.json, report.md,
 ghi out/context/                    trả JSON ở câu trả lời cuối                  agent.sarif, review.json, verdicts.json
```

- Lệnh `secagent --mode ...` (CI và máy) giữ nguyên hành vi; bên trong dùng chung code của bước 1 và 3.
- Engine `claude-code` chạy 3 bước riêng như trên, **chỉ trên máy**.
- Hai lệnh mới: `secagent-prepare` và `secagent-finalize`. Lệnh `secagent-validate` giữ nguyên.

### 4.2 Hợp đồng giữa các bước

**`secagent-prepare --repo . --base <sha> --head <sha> --sarif-dir sarif --requirements docs/security-requirements.md --out out [--no-requirements]`** ghi:

- `out/context/findings.json`: danh sách phát hiện sau gộp trùng, mỗi phần tử có `cluster_id`, `finding_ids`, công cụ, rule, mức độ, file, dòng, thông điệp đã che secret, cờ "nằm trong diff".
- `out/context/diff.patch`: diff base...head đã che secret.
- `out/context/requirements.md`: bản sao tài liệu quy tắc (không có nếu dùng `--no-requirements`).
- `out/context/task.md`: nhiệm vụ cho engine, dựng từ `prompts/system.md` + `prompts/review.md` cộng phần hướng dẫn riêng cho engine file (`prompts/engine_file.md`). Nội dung: đọc 3 file trên và code trong repo; với mỗi `cluster_id` nộp đúng một kết luận; săn thêm lỗi trong phần thay đổi; trả kết quả đúng schema trong **một khối JSON ở câu trả lời cuối** (engine không có quyền ghi file).

**`out/verdicts.json`** (`secagent-finalize` trích từ câu trả lời cuối của engine rồi ghi ra, để lưu vết):

```json
{
  "verdicts": [ /* VerdictArgs của secagent/models.py */ ],
  "new_findings": [ /* NewFindingArgs của secagent/models.py */ ]
}
```

**`secagent-finalize --repo . --base <sha> --head <sha> --sarif-dir sarif --requirements … --out out --execution-file <path> [--model <tên>] [--no-requirements]`**: gọi lại pha 0 với cùng tham số để cluster id trùng khớp, rồi:

- Kiểm tra schema bằng Pydantic. File thiếu hoặc không parse được → thoát `2`.
- **Độ phủ:** `cluster_id` không có kết luận → `NEEDS_REVIEW`. Engine file không hỏi lại được, nên khác `secagent` ở chỗ không có lượt bổ sung.
- **Chống bịa:** giống pha 2 của spec gốc.
- Đọc `--execution-file` (file kết quả của Claude Code, có số lượt, token, chi phí quy đổi, model) để điền `meta`: `model` là model thật, `strategy="claude-code"`, `tokens_in/out`, `cost_usd`, `duration_s`, `llm_calls` = số lượt. Ghi `trace.jsonl` từ file này.
- Sinh `report.json`, `report.md`, `agent.sarif`, `review.json` bằng chính `secagent.report`. Thoát `0`.
- `report.md` ghi rõ dòng "Engine: claude-code (model …)".

### 4.3 Không chạy trên CI

- `pr-security.yml` không có engine `claude-code` và không có secret Claude. Job `ai-security-agent` chỉ chạy `secagent` bằng `LLM_API_KEY`.
- **Vá kèm, độc lập với engine:** mọi job checkout code PR (`ai-security-agent`, `validate-patches`, `quality-gate`) đều xóa `out/` trước khi dùng, vì `out/` trong code PR do người mở PR kiểm soát. Trước đây một PR, kể cả từ fork, commit `out/agent-exit=0` cùng một `report.json` toàn FP có thể qua gate ở chế độ `ai-assisted`.

### 4.4 Trên máy (benchmark)

`agent/scripts/claude-engine.sh <repo> <out>` chạy `claude -p` với `task.md` và cấu hình trong `agent/engine.env`, xuất `--output-format stream-json --verbose` vào `<out>/engine-execution.jsonl` làm execution file. Benchmark gọi `prepare` → script này → `finalize`.

**Khóa quyền** (đã thử với Claude Code 2.1.330 thật):
- Chỉ có 3 công cụ Read, Grep, Glob (`--tools`), chế độ `dontAsk`: mọi thứ ngoài danh sách cho phép đều bị từ chối.
- Chỉ đọc trong thư mục làm việc. Cấm `.git/` và `sarif/` (SARIF thô chưa che secret; engine đọc phát hiện đã che ở `out/context/findings.json`).
- Không có công cụ chạy lệnh hay ghi file.
- Kết quả thử: đọc file ngoài repo, `.git/config`, `sarif/` và grep ra ngoài repo đều bị chặn.

**Mỗi lượt là một phiên mới và sạch:**
- không có lịch sử hội thoại;
- không nạp cài đặt, hook, plugin, MCP cá nhân (`--setting-sources project --strict-mcp-config --disable-slash-commands --no-session-persistence`);
- thư mục chạy không chứa đáp án.

Không dùng phiên Claude Code đang điều phối hay subagent của nó để chấm, vì phiên đó viết kịch bản và đáp án.

### 4.5 Cấu hình

- CLI `claude` trên máy, đăng nhập bằng tài khoản Claude. Máy đã có sẵn bản đi kèm extension VS Code (`claude.exe`), hoặc cài bằng `npm install -g @anthropic-ai/claude-code`. Script nhận đường dẫn qua `CLAUDE_BIN`.
- Secret `LLM_API_KEY` và các biến `LLM_*` giữ nguyên cho `secagent` trên CI.

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
- **Ánh xạ route → code (quyết định của mình):** `secagent-prepare` dùng công cụ AST `list_routes` để tìm hàm xử lý của mỗi `METHOD path` của ZAP, rồi gắn file và dòng của hàm đó vào finding làm vị trí liên quan (related location). Nhờ vậy kiểm tra chống bịa (`fp_is_anchored` trong `phases/check.py`) vẫn giữ nguyên độ chặt: kết luận FP cho finding ZAP phải trích đúng code của hàm xử lý hoặc file liên quan. Route không ánh xạ được → finding giữ nguyên; kết luận FP không neo được thì thành `NEEDS_REVIEW`. **Không** nới lỏng chống bịa kiểu Trivy.
- **Agent (cả hai engine):** nhận finding `zap` như mọi nguồn khác, kèm vị trí liên quan ở trên.
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
| Engine | khoảng 3–6 phút |

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
- Ghi `measured_detection: {sast_sca: bool, dast: bool}` vào `scenario.yaml` của từng kịch bản.
- Bảng kết quả chia nhóm theo nhãn đo được, không theo nhãn dự đoán.

**Chia dev/test:**
- Khoảng 5 kịch bản làm tập dev, dùng để chỉnh `prompts/engine_file.md`. Phần còn lại là tập test.
- `ground_truth.yaml` và prompt được chốt (commit) trước khi chạy tập test.

**Người viết kịch bản (thay quy ước tách người của Hợp đồng 3):** một người (Claude) viết toàn bộ kịch bản, đáp án và prompt, theo quyết định của người dùng. Biện pháp chống thiên vị:
1. **Thứ tự cố định:** viết tập dev → chỉnh prompt trên tập dev → **commit chốt prompt** → rồi mới viết kịch bản và đáp án tập test. Lịch sử git chứng minh thứ tự này.
2. **Engine không thấy đáp án:** engine chạy trong worktree ở commit kịch bản (từ `v0.3-baseline`, không có thư mục `benchmark/`), bằng một tiến trình `claude -p` riêng không có lịch sử hội thoại.
3. **Không chỉnh prompt sau khi đã thấy kết quả tập test.** Nếu buộc phải sửa thì chạy lại toàn bộ tập test và ghi rõ lý do trong báo cáo.
4. Báo cáo nêu rõ hạn chế "người viết đề và người chỉnh prompt là một".

### 8.3 Cấu hình

| Mã | Gồm | Số lần chạy |
|---|---|---|
| C1 | 6 nhóm công cụ quét, **kể cả CodeQL** | 1 (kết quả ổn định) |
| C1+DAST | C1 + ZAP 5 vai trò | 1 |
| **C6** | C1+DAST + engine `claude-code` (đủ tài liệu quy tắc) | 3 trên tập test, 1 trên tập dev |
| C6-noreq | C6 nhưng `--no-requirements` (ablation ngữ cảnh nghiệp vụ, thay C4 của spec gốc) | 1 trên tập test |
| C2, C2-thinking, C3, C5 | `secagent`: chạy khi có key, trên cùng bộ dữ liệu và cùng script | 3 |

**CodeQL trong benchmark (quyết định của mình):** `security/scan-local.sh` hiện bỏ CodeQL ("chỉ chạy trên CI"). Benchmark thêm CodeQL CLI ghim phiên bản và sha256 trong `tool-versions.env`, Python `build-mode none`, cùng bộ query như CI. Lý do: C1 phải khớp pipeline thật và khớp PR trưng bày, vì nhãn `measured_detection` phụ thuộc vào nó.

**Mọi cấu hình có engine nhận cùng đầu vào:** C2, C2-thinking, C3, C5 (khi chạy sau) cũng nhận SARIF của ZAP như C6. `run.py` lưu đầu ra của C1 và DAST theo commit kịch bản và dùng lại, không quét lại.

**Một model cho toàn bộ C6: `claude-sonnet-5-5`.**
- Lý do chọn: gói Max 5x; Sonnet dùng ít hạn mức hơn Opus nhiều, chạy nhanh hơn, và là lựa chọn thực tế cho review mỗi PR.
- Model ghi ở một chỗ là `agent/engine.env`, script máy đọc, ghi vào `meta.model`.

**Khối lượng ước tính** (khoảng 105–110 lượt engine):
- C6: 25 × 3 + 5 × 1;
- C6-noreq: 25 × 1;
- cộng vài lượt chỉnh prompt trên tập dev.

Mỗi lượt 3–6 phút, chạy không cần người trông. Hạn mức tính lại mỗi 5 giờ, nên toàn bộ benchmark có thể trải ra 2–3 ngày. Đổi model giữa chừng thì phải chạy lại toàn bộ C6. `run.py` chạy tiếp được từ chỗ dừng (bỏ qua lượt đã có kết quả) và tự chờ rồi thử lại khi chạm giới hạn sử dụng của gói.

Chi phí của C6 là **chi phí quy đổi theo bảng giá API** do Claude Code tự báo, vì chạy bằng gói thuê bao. Báo cáo ghi rõ điều này.

### 8.4 Cách chạy và lưu kết quả

`benchmark/run.py --config C1|C1+DAST|C6|C6-noreq|C2... --scenarios <list> --reps N`, với mỗi kịch bản:
1. Tạo worktree tạm ở `v0.3-baseline`, `git apply` patch, commit.
2. Chạy công cụ quét bằng `security/scan-local.sh`.
3. Với cấu hình có DAST: build image, `compose up` (tên project theo kịch bản), seed, chạy `run-dast.sh` cho 5 vai trò, rồi `compose down -v`.
4. Với cấu hình có engine: `prepare` → engine → `finalize`.
5. Ghi toàn bộ vào `benchmark/results/<run-id>/<config>/<scenario>/<rep>/`: SARIF, `report.json`, `trace.jsonl`, `timing.json`.

- `evaluate.py` sinh `summary.csv`, bảng Markdown và biểu đồ.
- Kết quả thô **được commit** để lưu vĩnh viễn. Artifact GitHub chỉ giữ tối đa 90 ngày.
- Ngoài ra mở **khoảng 5 PR trưng bày** (mỗi nhóm một kịch bản tiêu biểu) để chạy toàn bộ luồng trên GitHub. Comment và check được lưu cả khi PR đã đóng. Nhánh có lỗi không bao giờ được deploy.
- Phần AI trên PR trưng bày chỉ có khi `secagent` có API key; chưa có key thì gate chạy chế độ truyền thống. Kết quả của C6 nằm ở `benchmark/results/`.

**Chấm DAST:** finding `zap` khớp đáp án nếu cùng `route` (method + đường dẫn mẫu) và cùng nhóm CWE. Các luật chấm khác giữ như spec gốc mục 5.3.

## 9. Thứ tự làm và ranh giới PR

| Giai đoạn | PR | Cần label `security-reviewed` |
|---|---|---|
| 0 | Tài liệu này + kế hoạch | Không |
| 1 | Engine claude-code chạy trên máy (prepare/finalize, prompt, script) + vá `out/` trong workflow | Có (`.github/`, `agent/`) |
| 2 | DAST: `security/dast/`, job `dast-zap`/`dast`, gate nhận `zap` | Có |
| 3 | Ký image + `deploy/` + Kyverno | Có |
| 4 | Metrics trong app + `deploy/monitoring/` + script giả lập | Có thể không (nếu không sửa `.github/`, `security/`) |
| 5 | Benchmark: rule R-16–R-19, tag `v0.3-baseline`, kịch bản, run/evaluate, chạy, kết quả | Không (trừ khi sửa `security/`) |
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

- C6 dùng một coding agent thương mại (chạy trên máy, không chạy trên CI) làm engine suy luận. Kết quả đo năng lực của engine đó trong khung `secagent` (tiền xử lý, hậu kiểm, gate), không đo vòng lặp function calling tự viết. Vòng lặp này được đánh giá ở C2 khi có key.
- ZAP không thấy lỗi phân quyền giữa các vai trò, vì mỗi lần quét chỉ dùng một vai trò. Đây là giới hạn vốn có của DAST tự động và là điểm để so sánh với Agent.
- Deploy và giám sát chạy trên một cụm một node trên máy cá nhân. Tính sẵn sàng cao và lưu trữ lâu dài nằm ngoài phạm vi.
