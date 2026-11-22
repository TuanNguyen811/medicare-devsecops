<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 16 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 11 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `d9693a1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | checkov | CKV2_AWS_6 (checkov) | `infra/terraform/main.tf:320` | 0.95 |
| 🔴 TP | CRITICAL | checkov | CKV_AWS_54 (checkov) | `infra/terraform/main.tf:324` | 0.98 |
| 🔴 TP | CRITICAL | checkov | CKV_AWS_56 (checkov) | `infra/terraform/main.tf:324` | 0.98 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | MEDIUM | checkov | CKV_K8S_23 (checkov) | `infra/k8s/backup-cronjob.yaml:3` | 0.90 |
| 🔴 TP | MEDIUM | checkov | CKV_K8S_40 (checkov) | `infra/k8s/backup-cronjob.yaml:3` | 0.90 |
| 🔴 TP | MEDIUM | checkov | CKV_AWS_145 (checkov) | `infra/terraform/main.tf:320` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | agent | Image backup CronJob dùng digest giả và imagePullPolicy Always | `infra/k8s/backup-cronjob.yaml:33` | 0.50 |
| 🟢 FP | LOW | checkov | CKV_AWS_394 (checkov) | `infra/terraform/main.tf:5` | 0.85 |
| 🟢 FP | LOW | checkov | CKV_AWS_109 (checkov) | `infra/terraform/main.tf:15` | 0.85 |
| 🟢 FP | LOW | checkov | CKV_AWS_111 (checkov) | `infra/terraform/main.tf:15` | 0.85 |
| 🟢 FP | LOW | checkov | CKV_AWS_356 (checkov) | `infra/terraform/main.tf:15` | 0.85 |
| 🟢 FP | LOW | checkov | CKV2_AWS_5 (checkov) | `infra/terraform/main.tf:64` | 0.85 |
| 🟢 FP | LOW | checkov | CKV2_AWS_62 (checkov) | `infra/terraform/main.tf:175` | 0.80 |
| 🟢 FP | LOW | checkov | CKV_AWS_144 (checkov) | `infra/terraform/main.tf:175` | 0.80 |
| 🟢 FP | LOW | checkov | CKV2_AWS_62 (checkov) | `infra/terraform/main.tf:179` | 0.80 |
| 🟢 FP | LOW | checkov | CKV_AWS_144 (checkov) | `infra/terraform/main.tf:179` | 0.80 |
| 🟢 FP | LOW | checkov | CKV2_AWS_62 (checkov) | `infra/terraform/main.tf:320` | 0.75 |
| 🟢 FP | LOW | checkov | CKV_AWS_144 (checkov) | `infra/terraform/main.tf:320` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · CKV2_AWS_6 (checkov) — `infra/terraform/main.tf:320`

CWE-732 · OWASP A02 · độ tin cậy 0.95 · nguồn: checkov

**Phân tích:** Public access block của bucket backups đặt block_public_policy = false và restrict_public_buckets = false, trong khi bucket policy cho Principal "*" quyền s3:GetObject/s3:ListBucket. Kết quả là bản dump DB (chứa PII/bệnh án) đọc được công khai. Hai cấu hình này bị thiếu để chặn lỗi trên.

**Đề xuất sửa:** Trong aws_s3_bucket_public_access_block.backups đặt block_public_policy = true và restrict_public_buckets = true. Trong data.aws_iam_policy_document.backups, bỏ statement RestoreDownload với principal "*"; chỉ cấp s3:GetObject/s3:ListBucket cho role IAM của site standby (principals type AWS với ARN cụ thể). Giữ statement DenyInsecureTransport.

#### 🔴 TP · CRITICAL · CKV_AWS_54 (checkov) — `infra/terraform/main.tf:324`

CWE-732 · OWASP A02 · độ tin cậy 0.98 · nguồn: checkov

**Phân tích:** Bucket backup chứa dump PostgreSQL (dữ liệu bệnh nhân) đặt block_public_policy = false, đồng thời bucket policy cấp s3:GetObject/s3:ListBucket cho Principal "*" không có điều kiện. Kết hợp lại bucket công khai hoàn toàn cho mọi người trên Internet.

**Kịch bản khai thác:** Kẻ tấn công chạy `aws s3 ls s3://medicare-<env>-db-backups --no-sign-request`, liệt kê và tải toàn bộ dump DB chứa PII/bệnh án.

**Đề xuất sửa:** Trong infra/terraform/main.tf, resource aws_s3_bucket_public_access_block.backups đặt block_public_policy = true. Xóa statement RestoreDownload với principal "*" trong data.aws_iam_policy_document.backups; cấp quyền đọc bằng IAM role/principal ARN cụ thể của site standby. Giữ statement DenyInsecureTransport.

#### 🔴 TP · CRITICAL · CKV_AWS_56 (checkov) — `infra/terraform/main.tf:324`

CWE-732 · OWASP A02 · độ tin cậy 0.98 · nguồn: checkov

**Phân tích:** restrict_public_buckets = false cho phép policy với Principal "*" có hiệu lực công khai; kết hợp statement RestoreDownload, bucket chứa dump DB bị lộ cho mọi người.

**Kịch bản khai thác:** Bất kỳ ai không xác thực tải các file dump DB từ bucket qua HTTPS.

**Đề xuất sửa:** Trong aws_s3_bucket_public_access_block.backups đặt restrict_public_buckets = true (và block_public_policy = true). Bỏ principal "*" khỏi data.aws_iam_policy_document.backups, dùng principal cụ thể.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy nơi nào đặt X-Frame-Options hay CSP frame-ancestors; ZAP xác nhận thiếu header. PR này chỉ đổi hạ tầng, lỗi có sẵn từ trước.

**Đề xuất sửa:** Thêm middleware chung trong app FastAPI đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking; không có header bảo mật nào trong repo.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Middleware chung thêm header Content-Security-Policy chặt (default-src 'self').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · CKV_K8S_23 (checkov) — `infra/k8s/backup-cronjob.yaml:3`

CWE-250 · OWASP A02 · độ tin cậy 0.90 · nguồn: checkov

**Phân tích:** Pod securityContext đặt runAsUser: 0 / runAsGroup: 0 / fsGroup: 0, nên container backup chạy bằng root, không có runAsNonRoot. Job này giữ thông tin xác thực DB và AWS, vì vậy cần giảm quyền.

**Đề xuất sửa:** Trong infra/k8s/backup-cronjob.yaml, đặt runAsNonRoot: true và runAsUser/runAsGroup/fsGroup là UID cao không phải root (ví dụ 10001). Build lại image medicare-backup để chạy được bằng user này, và đảm bảo /backup (emptyDir) ghi được qua fsGroup.

#### 🔴 TP · MEDIUM · CKV_K8S_40 (checkov) — `infra/k8s/backup-cronjob.yaml:3`

CWE-250 · OWASP A02 · độ tin cậy 0.90 · nguồn: checkov

**Phân tích:** UID là 0, không phải UID cao (>=10000), nên có nguy cơ xung đột UID với host.

**Đề xuất sửa:** Đặt runAsUser, runAsGroup và fsGroup ≥ 10000 trong securityContext của CronJob, cùng với runAsNonRoot: true.

#### 🔴 TP · MEDIUM · CKV_AWS_145 (checkov) — `infra/terraform/main.tf:320`

CWE-311 · OWASP A04 · độ tin cậy 0.70 · nguồn: checkov

**Phân tích:** Bản dump DB chứa dữ liệu y tế nhưng mã hóa dùng AES256 (khóa do S3 quản lý) thay vì KMS key aws_kms_key.medicare đã mô tả để mã hóa S3, nên không có kiểm soát truy cập/audit ở mức khóa.

**Đề xuất sửa:** Trong aws_s3_bucket_server_side_encryption_configuration.backups đặt sse_algorithm = "aws:kms" và kms_master_key_id = aws_kms_key.medicare.arn, bật bucket_key_enabled = true.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /; không có cấu hình header nào.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân thiếu middleware header.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo; ZAP xác nhận thiếu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · Image backup CronJob dùng digest giả và imagePullPolicy Always — `infra/k8s/backup-cronjob.yaml:33`

CWE-494 · độ tin cậy 0.50 · nguồn: agent

**Phân tích:** Image được ghim bằng digest toàn số 0, là placeholder không hợp lệ. Job sẽ không chạy được, hoặc người dùng sẽ thay bằng tag không ghim. Cần dùng digest thật của image đã ký.

**Đề xuất sửa:** Thay bằng digest sha256 thật của image medicare-backup đã build và ký trong CI; không để digest placeholder.

<details><summary>🟢 Báo nhầm (FP): 11</summary>

- **CKV_AWS_394 (checkov)** — `infra/terraform/main.tf:5`: Code có từ trước, không nằm trong PR. Chỉ lấy 2 AZ đầu (count = 2) và file là hạ tầng mẫu chỉ được quét, không được apply. Đây là hardening, không phải lỗ hổng.
- **CKV_AWS_109 (checkov)** — `infra/terraform/main.tf:15`: Đây là key policy của KMS, nơi resources = ["*"] là chuẩn (chỉ ám chỉ chính key). Principal bị giới hạn ở root của account. Code có từ trước.
- **CKV_AWS_111 (checkov)** — `infra/terraform/main.tf:15`: Key policy KMS chuẩn, principal bị giới hạn ở root account. Code có từ trước.
- **CKV_AWS_356 (checkov)** — `infra/terraform/main.tf:15`: Trong key policy, "*" nghĩa là chính key này, và principal là root account. Code có từ trước.
- **CKV2_AWS_5 (checkov)** — `infra/terraform/main.tf:64`: Security group app được tham chiếu bởi rule ingress của DB (referenced_security_group_id), nên đã được gắn dùng. Code có từ trước.
- **CKV2_AWS_62 (checkov)** — `infra/terraform/main.tf:175`: Event notification là tính năng vận hành, không phải lỗ hổng. Bucket logs có từ trước và có public access block đầy đủ.
- **CKV_AWS_144 (checkov)** — `infra/terraform/main.tf:175`: Cross-region replication là yêu cầu về tính sẵn sàng, không phải lỗ hổng. Bucket logs có từ trước, hạ tầng mẫu chỉ quét.
- **CKV2_AWS_62 (checkov)** — `infra/terraform/main.tf:179`: Event notification là tính năng vận hành. Bucket imaging có từ trước, không thuộc PR.
- **CKV_AWS_144 (checkov)** — `infra/terraform/main.tf:179`: Cross-region replication là hardening về tính sẵn sàng. Bucket imaging có từ trước.
- **CKV2_AWS_62 (checkov)** — `infra/terraform/main.tf:320`: Event notification chỉ là tính năng vận hành/giám sát, không tạo ra lỗ hổng khai thác được. Bucket đã bật access logging sang bucket logs.
- **CKV_AWS_144 (checkov)** — `infra/terraform/main.tf:320`: Cross-region replication là yêu cầu DR/tính sẵn sàng, không phải lỗ hổng bảo mật. Bucket đã bật versioning. Rủi ro thực của bucket này được xử lý ở F21.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 105.8 s · 47 lần gọi LLM · 34 lần gọi công cụ · 185271 token vào / 17142 token ra · ≈ $0.3527 · chạm giới hạn: không</sub>
