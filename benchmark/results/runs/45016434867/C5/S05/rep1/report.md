<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c4b6f8b`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | SSTI: render mẫu Jinja do bác sĩ nhập bằng Environment không sandbox | `app/medicare/record/printing.py:97` | 0.95 |
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/slip.html:17` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · SSTI: render mẫu Jinja do bác sĩ nhập bằng Environment không sandbox — `app/medicare/record/printing.py:97`

CWE-1336 · OWASP A05 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** printing.py dùng jinja2.Environment(autoescape=True) thường (không SandboxedEnvironment) và gọi _env.from_string(body).render(...) với body do bác sĩ gửi qua POST /account/print-template. validate() chỉ parse cú pháp, không hạn chế thuộc tính/gọi hàm. Bác sĩ có thể dùng {{ ''.__class__.__mro__[1].__subclasses__() }} để thực thi mã tùy ý trên server (RCE), đọc biến môi trường (SECRET_KEY, DB URL) và toàn bộ dữ liệu bệnh án.

**Kịch bản khai thác:** Bác sĩ (hoặc tài khoản bác sĩ bị chiếm) lưu mẫu chứa payload SSTI truy cập __class__/__globals__ để chạy lệnh hệ thống, rồi mở /records/{id}/print để kích hoạt.

**Đề xuất sửa:** Trong printing.py thay Environment bằng jinja2.sandbox.ImmutableSandboxedEnvironment(autoescape=True) cho cả validate() và render_slip(); chặn truy cập thuộc tính dạng dunder. Tốt hơn nữa: bỏ Jinja do người dùng nhập, dùng mẫu chỉ có placeholder được allowlist (string.Template/thay thế biến cố định). Thêm timeout/giới hạn tài nguyên khi render và test payload SSTI.

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/slip.html:17`

CWE-79 · OWASP A05 · độ tin cậy 0.85 · nguồn: semgrep

**Phân tích:** slip.html chèn {{ slip | safe }}, trong đó slip là đầu ra của mẫu HTML do người dùng viết; nội dung này không được sanitize nên cho phép script tùy ý (stored XSS/HTML injection) trong origin của ứng dụng. Ngoài ra còn kết hợp với SSTI.

**Đề xuất sửa:** Không dùng |safe trên đầu ra của mẫu do người dùng nhập. Sanitize HTML bằng allowlist thẻ/thuộc tính (ví dụ bleach/nh3) trong printing.render_slip, hoặc chỉ cho phép định dạng hạn chế; đồng thời thêm CSP chặn script inline cho trang in.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong code không thấy middleware nào đặt X-Frame-Options/CSP frame-ancestors; main.py chỉ có CatchAllErrors, Session, Metrics. Thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Như F2: không có header chống clickjacking trên trang /login.

**Đề xuất sửa:** Dùng chung middleware security headers trong main.py: X-Frame-Options DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt; với tính năng slip chèn HTML người dùng, CSP càng cần thiết.

**Đề xuất sửa:** Thêm Content-Security-Policy (default-src 'self', script-src không cho inline) trong middleware ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options (không có trong code).

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; rủi ro thấp nhưng sửa chung bằng middleware.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff cho mọi response qua middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers ở main.py thêm X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 37.3 s · 15 lần gọi LLM · 14 lần gọi công cụ · 86302 token vào / 5516 token ra · ≈ $0.1459 · chạm giới hạn: không</sub>
