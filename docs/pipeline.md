# Pipeline DevSecOps

Pipeline chạy trên GitHub Actions, gồm 3 workflow, cộng thêm pre-commit trên máy lập trình viên.

## Công cụ ở từng giai đoạn

| Giai đoạn | Khi nào | Công cụ | Nơi cấu hình |
|---|---|---|---|
| **Code** | Trước mỗi commit, trên máy lập trình viên | Gitleaks, Ruff | `.pre-commit-config.yaml` |
| **Pull Request** | Mỗi lần mở hoặc cập nhật PR vào `main` | Semgrep, CodeQL, Bandit (SAST); Trivy (SCA); Gitleaks (Secret); Checkov, zizmor (IaC và workflow CI); **quality gate** | `.github/workflows/pr-security.yml` |
| **Merge vào main** | Mỗi lần push lên `main` | Quét toàn bộ (lên tab Security); build image, Trivy quét image, SBOM CycloneDX, push GHCR; staging tạm thời + smoke test | `.github/workflows/main-ci.yml` |
| **Hằng đêm** | 02:00 giờ Việt Nam | Trivy với cơ sở dữ liệu CVE mới nhất (thư viện + image `latest`) | `.github/workflows/nightly-sca.yml` |

Phiên bản mọi công cụ quét nằm ở **một file duy nhất**: [`security/tool-versions.env`](../security/tool-versions.env). Binary (trivy, gitleaks, actionlint) được tải bằng [`security/install-tools.sh`](../security/install-tools.sh) và kiểm tra sha256. Công cụ Python (semgrep, bandit, checkov, zizmor) được cài đúng phiên bản bằng `uvx`.

## Workflow Pull Request (`pr-security.yml`)

```
pull_request → main
 ├─ build-test ─────── pytest (254 test, PostgreSQL thật qua Testcontainers) + ruff + test của gate
 ├─ sast-semgrep ─────┐  chỉ báo phát hiện mới so với commit gốc (--baseline-commit)
 ├─ sast-bandit ──────┤
 ├─ sast-codeql ──────┤  security-extended, chỉ quét app/medicare
 ├─ sca-trivy ────────┤  mọi file khai báo thư viện trong repo (app/uv.lock); CSDL CVE cache theo ngày
 ├─ secret-gitleaks ──┤  chỉ các commit của PR, che giá trị secret (--redact)
 ├─ iac-checkov ──────┤  Checkov (Terraform, K8s, Dockerfile) + zizmor (workflow CI, chạy từ gốc repo)
 │                    ▼  mỗi job: artifact sarif-<tool> + upload lên tab Security
 └─ quality-gate ───── chặn hoặc cho qua (bắt buộc đạt, theo branch protection)
```

**Thời gian đo được** (lần chạy 42357232710, PR #3):

| Job | build-test | codeql | checkov+zizmor | semgrep | trivy | gitleaks | bandit | gate | **Tổng** |
|---|---|---|---|---|---|---|---|---|---|
| Giây | 44 | 40 | 29 | 27 | 26 | 18 | 17 | 5 | **54** |

Các job quét chạy song song nên tổng thời gian chỉ khoảng 1 phút, thấp hơn nhiều so với mục tiêu ≤ 5 phút của spec. Job AI Agent (kế hoạch C) sẽ chạy song song với build-test.

## Quality gate

Gate là script [`security/gate/gate.py`](../security/gate/gate.py), chỉ dùng thư viện chuẩn và có 68 test (một phần dùng SARIF thật của từng công cụ). Script đọc mọi file `sarif/*.sarif`, quy đổi mức độ rồi ra quyết định.

**Quy đổi mức độ:**
- Gitleaks luôn là HIGH.
- Nếu có `security-severity` (CVSS) ở kết quả hoặc ở rule: ≥ 9.0 là CRITICAL, ≥ 7.0 là HIGH, ≥ 4.0 là MEDIUM, còn lại LOW. Rule có thể nằm ở `tool.driver` hoặc `tool.extensions`; CodeQL đặt rule ở `extensions`.
  - Với Trivy, điểm này là CVSS chứ không phải nhãn của Trivy. Ví dụ CVE-2024-56326 được Trivy gắn MEDIUM nhưng có CVSS 7.8, nên gate xếp HIGH. Bước quét image ở main-ci thì dùng nhãn của Trivy.
- Nếu không có, dùng `level`: `error` là HIGH, `warning` là MEDIUM, `note`/không có là LOW.

**Phạm vi:** gate chỉ xét phát hiện mà PR có thể đã gây ra. Danh sách file thay đổi do gate tự tính bằng `git diff` **từ merge base** (`base...head`). Vì vậy các commit vào `main` sau khi PR rẽ nhánh không bị tính, tên file có dấu hay dấu cách được đọc đúng, và đường dẫn trong SARIF được giải mã percent-encoding. Một phát hiện được giữ lại khi thỏa một trong các điều kiện:
- Không có vị trí.
- Đến từ **Gitleaks**: công cụ này chỉ quét các commit của PR, nên secret đã commit rồi bị đổi tên hoặc xóa ở commit sau vẫn bị chặn (secret vẫn còn trong lịch sử của PR).
- Có **bất kỳ vị trí nào** nằm trong file thay đổi, tính cả vị trí chính, `relatedLocations` và các bước `codeFlows`. Ví dụ PR chỉ thêm route mới (nguồn dữ liệu) dẫn vào hàm cũ có lỗ hổng (điểm sink).
- Nằm trong **cùng thư mục Terraform** với một file `.tf`/`.tfvars` bị sửa. Lý do: Checkov tính cả biến, nên sửa `variables.tf` có thể làm lộ lỗi trong `main.tf`.

**Chính sách cấu hình nhạy cảm:** PR sửa `.github/**`, `security/**` hoặc file bỏ qua cảnh báo của công cụ quét (`.semgrepignore`, `.trivyignore`, `trivy.yaml`, `.gitleaksignore`, `.checkov.yaml`, `.bandit`, `zizmor.yml`, …) sẽ bị **chặn** cho tới khi có label `security-reviewed`. Label này là xác nhận của người review bảo mật.

**Chế độ** (biến repo `SECURITY_GATE_MODE`):

| Chế độ | Chặn khi |
|---|---|
| `traditional` (mặc định) | Có bất kỳ phát hiện HIGH/CRITICAL nào |
| `ai-assisted` (kế hoạch C) | Phát hiện HIGH/CRITICAL được Agent kết luận `TP`/`NEEDS_REVIEW`, hoặc **chưa được Agent thẩm định**. Nếu có nhiều kết luận cho cùng một phát hiện, chỉ cần một kết luận khác `FP` là chặn. Kết luận `FP` miễn chặn mức Critical chỉ khi PR có label `security-reviewed`. Ngoài ra chặn khi Agent tự tìm thêm lỗi HIGH/CRITICAL `TP` với độ tin cậy ≥ 0.7 |

**Fail-safe:**
- Agent lỗi (mã thoát 2, thiếu hoặc hỏng `report.json`) → gate quay về `traditional`.
- File SARIF hỏng → chặn.
- Một job quét hoặc build-test không thành công → chặn.

Bảng tóm tắt gate ghi vào job summary của Actions. Bảng này **không in nội dung `message`** của SARIF, vì message của Gitleaks có thể chứa secret.

## Bảo mật cho chính pipeline

| Biện pháp | Cách làm |
|---|---|
| Đặc quyền tối thiểu | `permissions: contents: read` ở cấp workflow. Job nào cần thêm quyền thì tự khai báo (`security-events: write`, `packages: write`) |
| Chống tấn công chuỗi cung ứng qua Action | Mọi `uses:` cố định bằng commit SHA 40 ký tự, kèm comment tag. Không dùng Action quét của bên thứ ba |
| Chống pwn request | Không dùng `pull_request_target`. PR từ fork không upload SARIF và không đọc được secret |
| Chống script injection | Mọi giá trị `${{ }}` đến từ người dùng (labels, SHA) được truyền qua `env:`, không nhúng vào `run:` |
| Checkout | `persist-credentials: false` ở mọi job |
| Tự kiểm tra | actionlint 1.7.12 và zizmor 1.32.0 (cũng chạy trong job iac-checkov, quét từ gốc repo nên phát hiện trong workflow mà PR sửa sẽ chặn PR): **0 phát hiện** |
| Không cho tắt cảnh báo trong code | Semgrep `--disable-nosem`, Bandit `--ignore-nosec`, Gitleaks `--ignore-gitleaks-allow`: comment `# nosemgrep`, `# nosec`, `gitleaks:allow` không có tác dụng. Checkov vẫn ghi kết quả bị `checkov:skip` vào SARIF (kèm `suppressions`) và gate vẫn đếm. File ignore của công cụ thì phải có label `security-reviewed` |
| Tái lập kết quả quét | Phiên bản công cụ cố định trong `tool-versions.env`; công cụ Python cài bằng `uvx --exclude-newer 2026-11-07T00:00:00Z`, nên thư viện phụ thuộc cũng cố định |
| Staging | Secret sinh ngẫu nhiên trong job bằng `openssl rand`, file `.env` có quyền 600, xóa ngay sau khi chạy |
| Branch protection `main` | Bắt buộc `build-test` và `quality-gate` đạt; cấm force-push và cấm xóa nhánh |

**Giới hạn đã biết** (ghi vào phần "mối đe dọa đối với tính hợp lệ" của báo cáo):
- Với sự kiện `pull_request`, GitHub chạy **workflow và `gate.py` của chính PR**. Người có quyền push nhánh có thể sửa workflow để bỏ qua gate. Chính sách cấu hình nhạy cảm chỉ làm việc này lộ ra (PR bị chặn cho tới khi có label `security-reviewed`), không ngăn được hoàn toàn. Muốn chặn hẳn cần review bắt buộc kèm CODEOWNERS cho `.github/` và `security/`, việc sẽ bật khi nhóm có thêm người review (hiện một người làm nên chưa thể tự duyệt PR của mình).
- Bộ rule `p/python` và `p/owasp-top-ten` của Semgrep lấy từ registry, không có phiên bản. Kết quả Semgrep có thể đổi theo ngày, nên benchmark lưu lại SARIF của từng lần chạy.
- Checkov bỏ qua (không báo lỗi) file Terraform có lỗi cú pháp.

## Main CI/CD (`main-ci.yml`)

Lần chạy đầu tiên trên `main`, ngay sau khi merge PR #3 (run 42360734824, thành công; lần chạy thử trước đó trên nhánh là 42357471271):

| Job | Giây | Kết quả |
|---|---|---|
| build-test | 40 | ✅ |
| full-scan (7 công cụ, upload SARIF theo category `main-*`) | 137 | ✅ (chỉ báo cáo, không chặn) |
| image (build → Trivy chặn nếu có CRITICAL đã có bản sửa → SBOM → push GHCR) | 48 | ✅ không có CRITICAL có bản sửa; SBOM khoảng 45 KB; push `ghcr.io/tuannguyen811/medicare-hms` với tag `sha` và `latest` |
| staging (compose up → smoke test → seed → down -v) | 36 | ✅ |

## Các trường hợp thực tế (dữ liệu cho báo cáo)

1. **Gate truyền thống chặn PR vì báo nhầm.** PR #3 thêm hạ tầng mẫu `infra/terraform` và `infra/k8s`. Gate ở chế độ `traditional` chặn với **10 phát hiện Checkov mức HIGH**, và cả 10 đều là FP hoặc rủi ro chấp nhận được (xem [`baseline-scan.md`](baseline-scan.md)). Nguyên nhân: Checkov không có mức độ nếu không có API key, nên mọi check không đạt đều mang level `error`. Đây đúng là vấn đề "alert fatigue / FP chặn luồng phát triển" mà Agent cần giải quyết.
2. **Gate chặn lỗ hổng thật** (PR #4, run 42361081208; PR đã đóng, nhánh đã xóa).
   - **Kịch bản:** lập trình viên thêm tính năng "tìm bệnh nhân theo số điện thoại", trong đó ghép chuỗi tìm kiếm thẳng vào SQL: `text(f"SELECT id FROM patients WHERE phone LIKE '{term}%'")`. Đoạn này chỉ chạy khi chuỗi bắt đầu bằng `0`, nên **255 test, kể cả các test bảo mật có sẵn, vẫn pass**. Ví dụ khai thác: `0' OR 1=1 --`.
   - **Kết quả:** build-test xanh, gate ở chế độ `traditional` **CHẶN** với 3 phát hiện mức HIGH, cùng ở `app/medicare/patient/service.py:55`:

     | Công cụ | Rule | Mức |
     |---|---|---|
     | CodeQL | `py/sql-injection` (lần theo luồng dữ liệu từ tham số `q` của route) | HIGH |
     | Semgrep | `medicare.sqlalchemy-text-fstring` (rule tự viết) | HIGH |
     | Semgrep | `avoid-sqlalchemy-text` (registry) | HIGH |
     | Bandit | `B608` | LOW, không chặn |

     Thời gian từ lúc mở PR đến khi gate có kết quả: **61 giây**.
   - **Nhận xét cho báo cáo:**
     - Ba công cụ cùng chỉ một dòng. Khi chuyển sang chế độ `ai-assisted`, Agent sẽ gộp ba phát hiện này thành một kết luận (`finding_ids` có 3 id).
     - Bandit đánh giá thấp lỗi SQL injection rõ ràng này.
     - Rule tự viết không bắt được dạng có biến trung gian (`sql = f"..."; text(sql)`). Dạng đó được dùng trong benchmark để đo phần Agent bổ sung so với công cụ quét.

## Chạy công cụ quét trên máy

```bash
bash security/scan-local.sh /tmp/scan HEAD          # quét bản export của commit HEAD bằng Docker
python3 security/gate/gate.py --sarif-dir /tmp/scan --mode traditional
```
