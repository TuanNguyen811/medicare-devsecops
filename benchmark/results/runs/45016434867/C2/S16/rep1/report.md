<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `5aac359`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/reschedule:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.75 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng chỉ có CatchAllErrorsMiddleware, SessionMiddleware, MetricsMiddleware; không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors (search_code không thấy). Trang HTML có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm một middleware trong app/medicare/main.py (create_app) đặt cho mọi response: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F1: trang /login không có X-Frame-Options/frame-ancestors, có thể bị clickjacking.

**Đề xuất sửa:** Dùng chung middleware security headers trong app/medicare/main.py: X-Frame-Options: DENY.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong code; ứng dụng y tế hiển thị dữ liệu người dùng nên thiếu lớp phòng thủ XSS.

**Đề xuất sửa:** Thêm header Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/reschedule:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục, gồm cả response của route reschedule mới.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục trên POST /patients.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục trên POST /patients/{patient_id}/edit.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /; cùng nguyên nhân toàn cục.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân toàn cục, rủi ro thấp.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options: nosniff; thiếu header trên toàn ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers trong app/medicare/main.py: thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 62.2 s · 24 lần gọi LLM · 14 lần gọi công cụ · 155307 token vào / 8889 token ra · ≈ $0.2039 · chạm giới hạn: không</sub>
