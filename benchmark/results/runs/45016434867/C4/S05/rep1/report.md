<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c4b6f8b`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Server-Side Template Injection: bác sĩ tự soạn mẫu Jinja, render bằng Environment không sandbox | `app/medicare/record/printing.py:38` | 0.95 |
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/slip.html:17` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · Server-Side Template Injection: bác sĩ tự soạn mẫu Jinja, render bằng Environment không sandbox — `app/medicare/record/printing.py:38`

CWE-1336 · OWASP A05 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** printing.py dùng jinja2.Environment(autoescape=True) thông thường (không phải SandboxedEnvironment) rồi gọi _env.from_string(body).render(...) với body do bác sĩ nhập. validate() chỉ kiểm tra độ dài và cú pháp, không hạn chế truy cập thuộc tính. Dù context chỉ chứa dict/chuỗi, payload như {{ ''.__class__.__mro__[1].__subclasses__() }} cho phép truy cập object Python và thực thi mã tùy ý (RCE) trên server. Ngoài ra, slip.html in kết quả bằng |safe nên bác sĩ cũng có thể lưu HTML/JS (stored XSS), mẫu này còn được dùng khi in phiếu.

**Kịch bản khai thác:** Tài khoản bác sĩ (hoặc kẻ chiếm được tài khoản đó) lưu mẫu chứa {{ ''.__class__.__mro__[1].__subclasses__() }} để tìm lớp như subprocess.Popen rồi thực thi lệnh khi mở /records/{id}/print, từ đó đọc biến môi trường, secret và toàn bộ DB bệnh nhân.

**Đề xuất sửa:** Trong printing.py thay Environment bằng jinja2.sandbox.SandboxedEnvironment (hoặc ImmutableSandboxedEnvironment) cho cả validate() và render_slip(). Cân nhắc dùng mẫu không phải Jinja (thay thế placeholder cố định theo danh sách VARIABLES). Chỉ cho phép các biến trong VARIABLES, chặn truy cập thuộc tính dấu gạch dưới, và bắt SecurityError khi lưu/in. Sanitize HTML đầu ra (ví dụ bleach/nh3 với whitelist thẻ) trước khi render, thay vì |safe trên chuỗi thô.

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/slip.html:17`

CWE-79 · OWASP A05 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** slip.html chèn {{ slip | safe }}, trong đó slip được render từ mẫu do bác sĩ kiểm soát (HTML tự do, lưu trong DB). Mẫu có thể chứa <script>, và người xem phiếu (kể cả bệnh nhân) chạy JS trong origin của ứng dụng. Autoescape của _env chỉ bảo vệ giá trị biến, không bảo vệ phần HTML của mẫu.

**Đề xuất sửa:** Làm sạch HTML của slip bằng thư viện whitelist (nh3/bleach) trong printing.render_slip trước khi trả về, và/hoặc phục vụ phiếu in với CSP chặt (script-src 'none'). Tránh |safe trên dữ liệu thô.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options, frame-ancestors hay CSP nào được đặt, nên phản hồi thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware chung (trong app factory) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào được đặt trong repo; trang /login bị ảnh hưởng.

**Đề xuất sửa:** Dùng middleware bảo mật chung đặt X-Frame-Options: DENY / frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo; đặc biệt đáng lo vì phiếu in dùng |safe.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', không inline script) qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options; /health cũng bị ảnh hưởng.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 39.7 s · 15 lần gọi LLM · 14 lần gọi công cụ · 68540 token vào / 5608 token ra · ≈ $0.1260 · chạm giới hạn: không</sub>
