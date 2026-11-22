<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c4b6f8b`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | SSTI dẫn tới RCE: Jinja2 Environment không sandbox render mẫu do bác sĩ nhập | `app/medicare/record/printing.py:38` | 0.93 |
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/slip.html:17` | 0.80 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /:0` | 0.50 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.50 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /login:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.50 |

### Chi tiết

#### 🔴 TP · CRITICAL · SSTI dẫn tới RCE: Jinja2 Environment không sandbox render mẫu do bác sĩ nhập — `app/medicare/record/printing.py:38`

CWE-1336 · OWASP A05 · độ tin cậy 0.93 · nguồn: agent

**Phân tích:** Mẫu `body` do bác sĩ gửi lên (Form) chỉ được kiểm tra độ dài và cú pháp (`_env.parse`), rồi được lưu và render bằng `Environment(autoescape=True)` thông thường (không phải SandboxedEnvironment) qua `_env.from_string(body).render(...)`. Context là dict/str Python thật nên có thể đi qua `__class__`/`__mro__`/`__globals__` để thực thi mã tùy ý trên server, đọc SECRET_KEY, DB, toàn bộ dữ liệu bệnh án. Đồng thời mẫu là HTML thô nên có thể chứa script (xem F1).

**Kịch bản khai thác:** Tài khoản bác sĩ (hoặc bị chiếm) lưu mẫu chứa `{{ patient.__class__.__mro__[1].__subclasses__() }}` hoặc chuỗi gadget tới `os.popen`, rồi mở /records/{id}/print để chạy lệnh trên server.

**Đề xuất sửa:** Trong printing.py dùng `jinja2.sandbox.ImmutableSandboxedEnvironment(autoescape=True)` thay cho Environment, và truyền vào context chỉ các giá trị chuỗi/số đơn giản. Cân nhắc bỏ hẳn Jinja cho mẫu người dùng: dùng thay thế placeholder an toàn (string.Template hoặc regex allowlist các biến trong VARIABLES) và làm sạch HTML bằng bộ allowlist (bleach/nh3). Thêm test chặn `__class__`, `__globals__`.

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/slip.html:17`

CWE-79 · OWASP A05 · độ tin cậy 0.80 · nguồn: semgrep

**Phân tích:** `{{ slip | safe }}` chèn nguyên chuỗi đã render từ mẫu HTML do bác sĩ tự viết, không có làm sạch HTML nên bác sĩ có thể chèn `<script>` chạy trong origin của ứng dụng (phiên bác sĩ, dữ liệu bệnh án). Dữ liệu biến được autoescape, nhưng phần thân mẫu thì không. Gốc rễ nghiêm trọng hơn là SSTI (đã báo riêng).

**Đề xuất sửa:** Làm sạch HTML của mẫu (allowlist thẻ/thuộc tính, bằng nh3/bleach) ngay khi lưu trong printing.validate/save_custom và/hoặc trước khi render trong render_slip; trả slip.html kèm header CSP chặt (script-src 'none'). Không dùng |safe trên nội dung chưa làm sạch.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** ZAP báo thiếu header chống clickjacking; không có bằng chứng middleware đặt X-Frame-Options/CSP frame-ancestors. Là cấu hình toàn cục, không thuộc logic PR.

**Đề xuất sửa:** Thêm middleware đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /; cấu hình toàn cục.

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cấu hình toàn cục, rủi ro thấp.

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff cho mọi route.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F2: trang /login thiếu header chống clickjacking.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY / frame-ancestors 'none'.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên /login; cấu hình toàn cục.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff cho mọi phản hồi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP; cấu hình toàn cục, đặc biệt đáng kể vì slip.html render HTML do bác sĩ nhập.

**Đề xuất sửa:** Thêm header Content-Security-Policy qua middleware chung (allowlist cdn.jsdelivr.net cho Bootstrap, không cho inline script).

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F7: thiếu CSP.

**Đề xuất sửa:** Đặt CSP bằng middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F7: thiếu CSP.

**Đề xuất sửa:** Đặt CSP bằng middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F7: thiếu CSP.

**Đề xuất sửa:** Đặt CSP bằng middleware chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 39.0 s · 13 lần gọi LLM · 12 lần gọi công cụ · 70820 token vào / 5905 token ra · ≈ $0.2074 · chạm giới hạn: không</sub>
