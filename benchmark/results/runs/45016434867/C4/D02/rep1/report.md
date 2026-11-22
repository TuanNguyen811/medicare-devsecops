<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `1e62304`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/insurance-check:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🟡 NEEDS_REVIEW | LOW | bandit | B404 (bandit) | `app/medicare/patient/insurance_check.py:10` | 0.90 |
| 🟢 FP | LOW | bandit | B603 (bandit) | `app/medicare/patient/insurance_check.py:57` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không tìm thấy nơi nào đặt X-Frame-Options hoặc frame-ancestors trong ứng dụng (search không có kết quả); main.py chỉ có Session, CatchAllErrors, Metrics middleware. Trang có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py, đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Như F3: không có header chống clickjacking nào được đặt trong ứng dụng; trang /login có thể bị nhúng.

**Đề xuất sửa:** Dùng chung middleware security headers trong app/medicare/main.py: X-Frame-Options DENY / frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu (search không có kết quả); là vấn đề cấu hình toàn cục.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Như F8: thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Như F8: thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Như F8: thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/insurance-check:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Như F8: thiếu CSP toàn cục, kể cả route insurance-check mới.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân chung, không có middleware đặt header.

**Đề xuất sửa:** Middleware security headers toàn cục trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff nào được đặt trong mã (search không có kết quả).

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🟡 NEEDS_REVIEW · LOW · B404 (bandit) — `app/medicare/patient/insurance_check.py:10`

CWE-78 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] B404 chỉ cảnh báo việc import subprocess; việc sử dụng được kiểm soát (argv list, không shell). Xem F2.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B603 (bandit)** — `app/medicare/patient/insurance_check.py:57`: subprocess.run nhận list argv, không shell=True; executable lấy từ cấu hình server (không do người dùng điều khiển); mã thẻ được kiểm tra bằng regex chặt, họ tên chuẩn hóa/giới hạn độ dài, mỗi giá trị dạng --name=value nên không thể thành option riêng. Có timeout. Không có command injection.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 57.0 s · 32 lần gọi LLM · 21 lần gọi công cụ · 127830 token vào / 8992 token ra · ≈ $0.1893 · chạm giới hạn: không</sub>
