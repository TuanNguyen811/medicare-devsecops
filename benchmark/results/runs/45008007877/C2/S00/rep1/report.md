<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `4705039`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** create_app trong app/medicare/main.py chỉ thêm middleware lỗi, session và metrics; không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors nên trang có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Trong create_app (app/medicare/main.py) thêm middleware security headers cho mọi response: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff, Content-Security-Policy chặt (default-src 'self'), Referrer-Policy.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking vì app không đặt X-Frame-Options/frame-ancestors ở bất kỳ middleware nào (app/medicare/main.py).

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu cả (tìm kiếm không thấy), làm giảm phòng thủ chiều sâu chống XSS.

**Đề xuất sửa:** Middleware security headers trong create_app (app/medicare/main.py) đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục, cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py) đặt CSP.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục, cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py) đặt CSP.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục, cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py) đặt CSP.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff, không có middleware nào đặt header này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware security headers trong create_app (app/medicare/main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** /health cũng thiếu X-Content-Type-Options vì header không được đặt toàn cục.

**Đề xuất sửa:** Middleware toàn cục trong create_app (app/medicare/main.py) đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options: nosniff trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers trong create_app (app/medicare/main.py) thêm X-Content-Type-Options: nosniff cho mọi response, gồm cả /static.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 38.8 s · 15 lần gọi LLM · 13 lần gọi công cụ · 74555 token vào / 5578 token ra · ≈ $0.1106 · chạm giới hạn: không</sub>
