<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c4b6f8b`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Server-Side Template Injection (RCE) qua mẫu in phiếu khám do bác sĩ nhập | `app/medicare/record/printing.py:96` | 0.95 |
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/slip.html:17` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |

### Chi tiết

#### 🔴 TP · CRITICAL · Server-Side Template Injection (RCE) qua mẫu in phiếu khám do bác sĩ nhập — `app/medicare/record/printing.py:96`

CWE-1336 · OWASP A05 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** printing.py dùng jinja2.Environment thường (không sandbox) và render chuỗi template do người dùng (bác sĩ) cung cấp qua _env.from_string(body).render(). validate() chỉ kiểm tra độ dài và cú pháp. autoescape không ngăn truy cập thuộc tính/đối tượng Python, nên có thể dùng các biểu thức như ''.__class__.__mro__... để thực thi mã tùy ý trên server, đọc SECRET_KEY, DB và toàn bộ dữ liệu bệnh án.

**Kịch bản khai thác:** Tài khoản bác sĩ (bị chiếm hoặc độc hại) lưu mẫu chứa {{ ''.__class__.__mro__[1].__subclasses__() }} dẫn tới gọi os/subprocess, sau đó mở /records/{id}/print để thực thi mã trên server và đánh cắp dữ liệu/secret.

**Đề xuất sửa:** Trong printing.py dùng jinja2.sandbox.SandboxedEnvironment (autoescape=True) thay cho Environment cho cả validate() và render_slip(); chỉ truyền dict giá trị thuần như hiện tại. Tốt hơn: không cho nhập Jinja, chỉ hỗ trợ placeholder thay thế cố định theo allowlist (VARIABLES). Đồng thời giới hạn thời gian/kích thước render và sanitize HTML (allowlist thẻ, bỏ script) trước khi lưu.

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/slip.html:17`

CWE-79 · OWASP A05 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** slip.html chèn {{ slip | safe }}, trong đó slip là HTML sinh từ mẫu do bác sĩ nhập tự do (không sanitize), nên bác sĩ có thể chèn <script> chạy trong origin của ứng dụng (stored XSS), tại trang chứa dữ liệu bệnh án. Mẫu chỉ áp dụng cho chính bác sĩ xem nhưng vẫn vi phạm quy tắc cấm |safe trên dữ liệu người dùng và kết hợp với SSTI làm tăng rủi ro.

**Đề xuất sửa:** Không dùng |safe trên nội dung mẫu do người dùng nhập. Sanitize HTML của mẫu bằng allowlist thẻ/thuộc tính (ví dụ bleach/nh3) khi lưu và khi render, hoặc chỉ cho placeholder và render phần còn lại đã escape; thêm CSP chặn script inline cho trang /records/{id}/print.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options hay frame-ancestors nào được đặt, nên ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers dùng chung trong app (X-Frame-Options: DENY hoặc CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo (tìm kiếm không có kết quả).

**Đề xuất sửa:** Thêm middleware security headers chung: X-Frame-Options DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware security headers chung đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung (default-src 'self', cấm inline script).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff trong repo; endpoint /health cũng bị ảnh hưởng.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 42.7 s · 15 lần gọi LLM · 14 lần gọi công cụ · 106679 token vào / 5712 token ra · ≈ $0.1483 · chạm giới hạn: không</sub>
