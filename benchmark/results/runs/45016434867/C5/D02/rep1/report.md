<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `1e62304`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/insurance-check:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🟢 FP | LOW | bandit | B404 (bandit) | `app/medicare/patient/insurance_check.py:10` | 0.90 |
| 🟢 FP | LOW | bandit | B603 (bandit) | `app/medicare/patient/insurance_check.py:57` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy ứng dụng đặt X-Frame-Options hay CSP frame-ancestors; ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers dùng chung (trong app factory) đặt X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware security headers chung: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/insurance-check:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo; route insurance-check mới cũng không có.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers chung để áp dụng cho cả route mới.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, kể cả /health; mức độ thấp.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers chung áp dụng cho mọi route.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers chung, thêm X-Content-Type-Options: nosniff cho mọi response.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **B404 (bandit)** — `app/medicare/patient/insurance_check.py:10`: B404 chỉ cảnh báo việc import subprocess; việc sử dụng được xử lý an toàn (argv list, không shell, giá trị được kiểm tra).
- **B603 (bandit)** — `app/medicare/patient/insurance_check.py:57`: subprocess.run nhận list argv, không shell=True nên không có shell injection. Mã thẻ được kiểm tra bằng is_valid_insurance_number, họ tên chuẩn hóa/giới hạn, ngày được format; mọi giá trị dạng --name=value nên không thành option riêng. Executable lấy từ settings (env), không từ người dùng.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 53.3 s · 29 lần gọi LLM · 18 lần gọi công cụ · 130630 token vào / 8610 token ra · ≈ $0.2113 · chạm giới hạn: không</sub>
