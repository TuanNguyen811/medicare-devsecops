<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 8 lỗi cần sửa (2 do Agent tự tìm, công cụ quét không báo) · 🟡 2 cần người xem

🟢 9 báo nhầm của công cụ quét đã được gỡ · 📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `4d0daa3`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | CKV2_AWS_6 (checkov) | `infra/terraform/main.tf:320` | checkov | 0.95 |
| 🔴 TP | CRITICAL | CKV_AWS_54 (checkov) | `infra/terraform/main.tf:324` | checkov | 0.95 |
| 🔴 TP | CRITICAL | CKV_AWS_56 (checkov) | `infra/terraform/main.tf:324` | checkov | 0.95 |
| 🔴 TP | CRITICAL | Bucket policy backups cho phép Principal "*" đọc/liệt kê dump DB | `infra/terraform/main.tf:371` | agent | 0.95 |
| 🔴 TP | MEDIUM | CKV_K8S_23 (checkov) | `infra/k8s/backup-cronjob.yaml:3` | checkov | 0.90 |
| 🔴 TP | MEDIUM | CKV_K8S_40 (checkov) | `infra/k8s/backup-cronjob.yaml:3` | checkov | 0.90 |
| 🔴 TP | MEDIUM | CKV_AWS_145 (checkov) | `infra/terraform/main.tf:320` | checkov | 0.70 |
| 🔴 TP | LOW | Image CronJob backup dùng digest giả toàn số 0 và imagePullPolicy Always | `infra/k8s/backup-cronjob.yaml:33` | agent | 0.50 |
| 🟡 NEEDS_REVIEW | LOW | CKV2_AWS_62 (checkov) | `infra/terraform/main.tf:320` | checkov | 0.65 |
| 🟡 NEEDS_REVIEW | LOW | CKV_AWS_144 (checkov) | `infra/terraform/main.tf:320` | checkov | 0.60 |

### Chi tiết

#### 🔴 TP · CRITICAL · CKV2_AWS_6 (checkov) — `infra/terraform/main.tf:320`

CWE-284 · OWASP A01 · độ tin cậy 0.95 · nguồn: checkov

**Phân tích:** Public access block của bucket backups đặt block_public_policy=false và restrict_public_buckets=false, trong khi bucket policy cho Principal "*" s3:GetObject/ListBucket. Bucket chứa bản dump PostgreSQL (dữ liệu bệnh nhân, PII/PHI) nên bị công khai ra Internet. Khác với logs/imaging đều bật cả 4 cờ.

**Đề xuất sửa:** Trong aws_s3_bucket_public_access_block.backups đặt block_public_policy = true và restrict_public_buckets = true (giống logs/imaging). Xóa statement RestoreDownload với principal "*" trong data.aws_iam_policy_document.backups; chỉ cấp quyền cho role IAM cụ thể của job backup/restore.

#### 🔴 TP · CRITICAL · CKV_AWS_54 (checkov) — `infra/terraform/main.tf:324`

CWE-732 · OWASP A02 · độ tin cậy 0.95 · nguồn: checkov

**Phân tích:** Bucket chứa bản dump PostgreSQL (dữ liệu bệnh nhân) có block_public_policy = false, và policy "RestoreDownload" cấp s3:GetObject/s3:ListBucket cho principal "*" không điều kiện. Bất kỳ ai trên internet đều liệt kê và tải được backup. Mã hóa AES256 không giúp vì S3 tự giải mã khi trả về.

**Kịch bản khai thác:** Kẻ tấn công chạy aws s3 ls/cp ẩn danh trên bucket medicare-<env>-db-backups và tải toàn bộ dump CSDL chứa CCCD, BHYT, bệnh án.

**Đề xuất sửa:** Trong aws_s3_bucket_public_access_block.backups đặt block_public_policy và restrict_public_buckets = true. Xóa statement RestoreDownload với principal "*" trong data.aws_iam_policy_document.backups; chỉ cấp s3:GetObject/ListBucket cho IAM role cụ thể của site standby. Giữ statement DenyInsecureTransport.

#### 🔴 TP · CRITICAL · CKV_AWS_56 (checkov) — `infra/terraform/main.tf:324`

CWE-732 · OWASP A02 · độ tin cậy 0.95 · nguồn: checkov

**Phân tích:** restrict_public_buckets = false cho phép policy công khai (Principal "*") có hiệu lực, nên bucket backup thực sự truy cập được từ internet.

**Kịch bản khai thác:** Như F26: tải ẩn danh các bản dump chứa dữ liệu y tế.

**Đề xuất sửa:** Đặt restrict_public_buckets = true (và block_public_policy = true) trong aws_s3_bucket_public_access_block.backups; cấp quyền restore qua IAM role cụ thể thay vì principal "*".

#### 🔴 TP · CRITICAL · Bucket policy backups cho phép Principal "*" đọc/liệt kê dump DB — `infra/terraform/main.tf:371`

CWE-732 · OWASP A01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Statement RestoreDownload (Allow mặc định) cấp s3:GetObject và s3:ListBucket cho mọi principal (type "*", "*") trên bucket backups. Kết hợp với public access block đã tắt, bất kỳ ai không cần xác thực đều tải được bản dump PostgreSQL chứa dữ liệu bệnh nhân. Statement Deny chỉ ép HTTPS, không giới hạn người dùng.

**Kịch bản khai thác:** Kẻ tấn công chạy aws s3 ls / aws s3 cp --no-sign-request trên medicare-<env>-db-backups, tải toàn bộ dump chứa CCCD, BHYT, bệnh án.

**Đề xuất sửa:** Xóa principal "*" khỏi statement RestoreDownload trong data.aws_iam_policy_document.backups; chỉ cho phép ARN role IAM cụ thể của site standby/job restore (và role của job backup), kèm bật đủ 4 cờ public access block.

#### 🔴 TP · MEDIUM · CKV_K8S_23 (checkov) — `infra/k8s/backup-cronjob.yaml:3`

CWE-250 · OWASP A02 · độ tin cậy 0.90 · nguồn: checkov

**Phân tích:** Pod CronJob chạy với runAsUser: 0 (root) ở mức pod, không có runAsNonRoot. Job sao lưu chỉ cần ghi vào /backup (emptyDir) nên không cần root.

**Đề xuất sửa:** Trong infra/k8s/backup-cronjob.yaml, đặt runAsNonRoot: true và runAsUser/runAsGroup/fsGroup là UID cao không phải 0 (ví dụ 10001); đảm bảo image medicare-backup chạy được với user đó.

#### 🔴 TP · MEDIUM · CKV_K8S_40 (checkov) — `infra/k8s/backup-cronjob.yaml:3`

CWE-250 · OWASP A02 · độ tin cậy 0.90 · nguồn: checkov

**Phân tích:** UID 0 được đặt tường minh, trái với yêu cầu UID cao (>=10000).

**Đề xuất sửa:** Đổi runAsUser/runAsGroup/fsGroup sang UID/GID >= 10000 trong securityContext của pod, cùng runAsNonRoot: true.

#### 🔴 TP · MEDIUM · CKV_AWS_145 (checkov) — `infra/terraform/main.tf:320`

CWE-311 · OWASP A04 · độ tin cậy 0.70 · nguồn: checkov

**Phân tích:** Bucket backups chứa dump DB y tế nhưng dùng SSE-S3 (AES256) thay vì KMS key aws_kms_key.medicare đã có sẵn ("Encrypts MediCare data at rest (RDS, S3, logs)"), làm mất kiểm soát truy cập khóa riêng.

**Đề xuất sửa:** Trong aws_s3_bucket_server_side_encryption_configuration.backups đặt sse_algorithm = "aws:kms" và kms_master_key_id = aws_kms_key.medicare.arn (có thể bật bucket_key_enabled).

#### 🔴 TP · LOW · Image CronJob backup dùng digest giả toàn số 0 và imagePullPolicy Always — `infra/k8s/backup-cronjob.yaml:33`

CWE-1104 · OWASP A03 · độ tin cậy 0.50 · nguồn: agent

**Phân tích:** Digest placeholder toàn 0 không phải image thật được xác minh; job có quyền AWS và kết nối DB nên cần pin image đã ký. Ngoài ra bucket "medicare-staging-db-backups" bị hard-code, không theo môi trường.

**Đề xuất sửa:** Thay digest bằng digest thật của image đã build và ký trong CI; tham số hóa tên bucket theo môi trường (ví dụ qua kustomize/overlay) thay vì hard-code staging.

#### 🟡 NEEDS_REVIEW · LOW · CKV2_AWS_62 (checkov) — `infra/terraform/main.tf:320`

độ tin cậy 0.65 · nguồn: checkov

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] Event notification là tùy chọn quan sát, không phải lỗ hổng khai thác được; vấn đề thật của bucket được xử lý ở F22. Bucket đã bật logging truy cập.

#### 🟡 NEEDS_REVIEW · LOW · CKV_AWS_144 (checkov) — `infra/terraform/main.tf:320`

độ tin cậy 0.60 · nguồn: checkov

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] Cross-region replication là tùy chọn DR/độ sẵn sàng, không phải lỗ hổng bảo mật; bucket đã bật versioning và lifecycle.

<details><summary>🟢 Báo nhầm của công cụ quét đã gỡ: 9</summary>

- **CKV_AWS_394 (checkov)** — `infra/terraform/main.tf:5`: Code có từ trước, không thuộc PR. Data source chỉ lấy tên AZ với count cố định = 2; không phải lỗ hổng bảo mật. Header nói đây là hạ tầng mẫu, chỉ quét bằng Checkov, không apply.
- **CKV_AWS_109 (checkov)** — `infra/terraform/main.tf:15`: Đây là key policy KMS, trong đó resources ["*"] nghĩa là chính key đó; chỉ principal là root của tài khoản. Đây là mẫu chuẩn của AWS. Code có từ trước, ngoài PR.
- **CKV_AWS_111 (checkov)** — `infra/terraform/main.tf:15`: Key policy KMS mặc định cho root tài khoản; resource "*" chỉ là chính key. Có từ trước, ngoài PR.
- **CKV_AWS_356 (checkov)** — `infra/terraform/main.tf:15`: Trong resource-based key policy của KMS, "*" chỉ chính key được gắn policy; không mở rộng sang tài nguyên khác. Có từ trước, ngoài PR.
- **CKV2_AWS_5 (checkov)** — `infra/terraform/main.tf:64`: Security group không có rule mở và chưa gắn vào tài nguyên trong mẫu hạ tầng; không tạo bề mặt tấn công. Có từ trước, ngoài PR.
- **CKV2_AWS_62 (checkov)** — `infra/terraform/main.tf:175`: Thông báo sự kiện S3 là tùy chọn vận hành, không phải lỗ hổng. Bucket logs có từ trước, ngoài PR.
- **CKV_AWS_144 (checkov)** — `infra/terraform/main.tf:175`: Nhân bản cross-region là tùy chọn DR, không phải lỗ hổng. Bucket logs có từ trước, ngoài PR.
- **CKV2_AWS_62 (checkov)** — `infra/terraform/main.tf:179`: Event notification là tùy chọn vận hành; bucket imaging đã chặn public access. Có từ trước, ngoài PR.
- **CKV_AWS_144 (checkov)** — `infra/terraform/main.tf:179`: Replication cross-region là tùy chọn DR; bucket imaging đã chặn public access. Có từ trước, ngoài PR.

</details>

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Không tìm thấy X-Frame-Options hay CSP frame-ancestors, cũng không có middleware thêm security header; main.py chỉ có CatchAllErrors, Session, Metrics. Ứng dụng thực sự thiếu header (PR chỉ đổi infra nên đây là vấn đề sẵn có). | Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có Content-Security-Policy nào được đặt trong ứng dụng (tìm kiếm không có kết quả). | Middleware chung trong app/medicare/main.py thêm Content-Security-Policy chặt (default-src 'self'; frame-ancestors 'none'). |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options; không có code đặt header này. | Middleware chung thêm X-Content-Type-Options: nosniff. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Không có code nào đặt X-Content-Type-Options trong repo. | Middleware chung trong app/medicare/main.py thêm X-Content-Type-Options: nosniff. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 137.4 s · 52 lần gọi LLM · 38 lần gọi công cụ · 204363 token vào / 19130 token ra · ≈ $0.3982 · chạm giới hạn: không</sub>
