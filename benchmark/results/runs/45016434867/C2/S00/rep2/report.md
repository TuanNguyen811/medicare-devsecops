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
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** create_app chỉ thêm CatchAllErrorsMiddleware, SessionMiddleware, MetricsMiddleware; không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors. Trang có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Thêm một SecurityHeadersMiddleware trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY, Content-Security-Policy có frame-ancestors 'none', và X-Content-Type-Options: nosniff trên mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F1: trang /login (nhập mật khẩu) không có header chống clickjacking vì app không có middleware security headers.

**Đề xuất sửa:** Dùng chung SecurityHeadersMiddleware trong create_app (main.py) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu cả; app xử lý dữ liệu y tế nên cần CSP làm lớp phòng thủ chống XSS.

**Đề xuất sửa:** Đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none', không unsafe-inline) trong SecurityHeadersMiddleware ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân với F6.

**Đề xuất sửa:** Đặt CSP toàn cục trong SecurityHeadersMiddleware (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân với F6.

**Đề xuất sửa:** Đặt CSP toàn cục trong SecurityHeadersMiddleware (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân với F6.

**Đề xuất sửa:** Đặt CSP toàn cục trong SecurityHeadersMiddleware (main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /; không có middleware đặt header này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua SecurityHeadersMiddleware trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân, không có middleware đặt header. Rủi ro thấp nhưng sửa một lần ở middleware.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua SecurityHeadersMiddleware trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options trong ứng dụng (search không thấy).

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong SecurityHeadersMiddleware (main.py) đặt X-Content-Type-Options: nosniff cho mọi response, gồm cả /static.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 64.1 s · 23 lần gọi LLM · 13 lần gọi công cụ · 90940 token vào / 8659 token ra · ≈ $0.1416 · chạm giới hạn: không</sub>
