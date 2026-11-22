<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c4b6f8b`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | SSTI dẫn tới RCE: render mẫu phiếu khám do bác sĩ nhập bằng Jinja2 Environment không sandbox | `app/medicare/record/printing.py:97` | 0.95 |
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

#### 🔴 TP · CRITICAL · SSTI dẫn tới RCE: render mẫu phiếu khám do bác sĩ nhập bằng Jinja2 Environment không sandbox — `app/medicare/record/printing.py:97`

CWE-1336 · OWASP A05 · vi phạm R-10 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** printing.py dùng jinja2.Environment(autoescape=True) thường (không phải SandboxedEnvironment) rồi gọi _env.from_string(body).render(...) với body là dữ liệu do bác sĩ nhập và lưu trong DB. validate() chỉ kiểm tra độ dài và cú pháp, không hạn chế truy cập thuộc tính. Người dùng có thể dùng {{ cycler.__init__.__globals__.os.popen('...').read() }} để thực thi lệnh trên server, đọc SECRET_KEY, DB và toàn bộ PII. Output còn được chèn qua |safe nên cũng cho phép HTML/JS tùy ý.

**Kịch bản khai thác:** Tài khoản bác sĩ (hoặc bị chiếm) lưu mẫu chứa {{ cycler.__init__.__globals__.os.popen('env').read() }} tại POST /account/print-template, rồi mở /records/{id}/print để chạy lệnh và lấy secret/dữ liệu bệnh nhân.

**Đề xuất sửa:** Trong printing.py thay Environment bằng jinja2.sandbox.ImmutableSandboxedEnvironment (autoescape=True) cho cả validate() và render_slip(); cân nhắc bỏ globals mặc định (cycler, joiner, namespace, lipsum). Tốt hơn là bỏ hẳn Jinja cho người dùng: dùng cú pháp placeholder đơn giản thay thế từ allowlist VARIABLES (string.Template/regex), và escape giá trị. Sanitize HTML đầu ra bằng allowlist (ví dụ bleach/nh3) trước khi chèn vào slip.html.

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/slip.html:17`

CWE-79 · OWASP A05 · vi phạm R-10 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** slip.html chèn {{ slip | safe }}, trong đó slip là kết quả render từ mẫu do bác sĩ tự nhập HTML tùy ý (kể cả <script>) và lưu DB, không có sanitize. Đây là XSS lưu trữ trên trang chứa dữ liệu bệnh án, cùng origin với session.

**Đề xuất sửa:** Không dùng |safe trên nội dung do người dùng kiểm soát. Sanitize đầu ra trong printing.render_slip bằng allowlist thẻ/thuộc tính (nh3/bleach), cấm script, on*, javascript:, và thêm CSP cho trang in. Hoặc chỉ cho phép placeholder, không cho HTML tự do.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay frame-ancestors ở bất kỳ đâu trong repo, nên ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware toàn cục trong app (FastAPI) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Frame-Options/frame-ancestors trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options ở đâu trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo; đặc biệt cần vì PR cho phép HTML tùy ý trong phiếu in.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục (default-src 'self', không cho script inline).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo (áp dụng cả /health).

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 38.6 s · 15 lần gọi LLM · 14 lần gọi công cụ · 84821 token vào / 5606 token ra · ≈ $0.0902 · chạm giới hạn: không</sub>
