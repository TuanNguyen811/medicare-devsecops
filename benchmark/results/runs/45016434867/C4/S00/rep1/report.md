<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `4705039`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app trong app/medicare/main.py chỉ thêm CatchAllErrorsMiddleware, SessionMiddleware và MetricsMiddleware. Không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors, nên trang có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Thêm một SecurityHeadersMiddleware trong create_app (app/medicare/main.py) để đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking vì app/medicare/main.py không có middleware đặt header. Đây là trang nhập thông tin đăng nhập nên rủi ro cao hơn.

**Đề xuất sửa:** Dùng chung SecurityHeadersMiddleware trong create_app (main.py) để đặt X-Frame-Options: DENY và frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có code nào trong ứng dụng đặt X-Content-Type-Options, nên trình duyệt có thể MIME-sniff response.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong SecurityHeadersMiddleware ở main.py, đặt X-Content-Type-Options: nosniff cho mọi response, gồm cả /static.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu (main.py không có middleware nào làm việc này), nên thiếu lớp phòng thủ chiều sâu chống XSS.

**Đề xuất sửa:** Thêm header Content-Security-Policy chặt (default-src 'self'; frame-ancestors 'none') trong SecurityHeadersMiddleware ở main.py, áp dụng cho cả response của POST và redirect.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP trên toàn ứng dụng, vì main.py không có middleware đặt header bảo mật.

**Đề xuất sửa:** Đặt CSP toàn cục bằng SecurityHeadersMiddleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP trên toàn ứng dụng, vì main.py không có middleware đặt header bảo mật.

**Đề xuất sửa:** Đặt CSP toàn cục bằng SecurityHeadersMiddleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP trên toàn ứng dụng, vì main.py không có middleware đặt header bảo mật.

**Đề xuất sửa:** Đặt CSP toàn cục bằng SecurityHeadersMiddleware trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options: nosniff.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong SecurityHeadersMiddleware ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Endpoint /health cũng thiếu X-Content-Type-Options vì không có middleware toàn cục. Rủi ro thấp vì response là JSON.

**Đề xuất sửa:** Middleware toàn cục trong main.py sẽ phủ cả /health.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 45.5 s · 24 lần gọi LLM · 14 lần gọi công cụ · 67484 token vào / 7584 token ra · ≈ $0.1345 · chạm giới hạn: không</sub>
