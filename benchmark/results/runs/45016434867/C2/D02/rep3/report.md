<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `1e62304`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/insurance-check:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🟢 FP | LOW | bandit | B404 (bandit) | `app/medicare/patient/insurance_check.py:10` | 0.90 |
| 🟢 FP | LOW | bandit | B603 (bandit) | `app/medicare/patient/insurance_check.py:57` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay frame-ancestors; ứng dụng không đặt header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers trong app factory (app/medicare), đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Frame-Options/frame-ancestors trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware security headers chung: X-Frame-Options: DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung (default-src 'self', frame-ancestors 'none') cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/insurance-check:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo; route insurance-check mới cũng thiếu header này.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung để áp dụng cho mọi route kể cả route mới.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt header nosniff nào.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt header nosniff; áp dụng cả /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung áp dụng cho mọi route.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt header nosniff nào.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers chung.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **B404 (bandit)** — `app/medicare/patient/insurance_check.py:10`: B404 chỉ cảnh báo việc import subprocess. Việc sử dụng được kiểm soát: danh sách tham số, không shell, đường dẫn executable lấy từ cấu hình.
- **B603 (bandit)** — `app/medicare/patient/insurance_check.py:57`: subprocess.run nhận list, không shell=True, nên không có shell injection. Executable lấy từ settings (env), không từ người dùng. Mã thẻ được kiểm tra regex ASCII chặt; tên được chuẩn hóa/giới hạn và nằm trong dạng --ho-ten=value nên không thành option riêng. Có timeout.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 56.9 s · 28 lần gọi LLM · 17 lần gọi công cụ · 126666 token vào / 8156 token ra · ≈ $0.1434 · chạm giới hạn: không</sub>
