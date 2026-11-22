<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 2 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `c4c7b25`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | Server-Side Template Injection: bác sĩ tự viết template Jinja2 chạy trên Environment không sandbox | `app/medicare/record/printing.py:97` | agent | 0.93 |
| 🔴 TP | HIGH | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/slip.html:17` | semgrep | 0.85 |

### Chi tiết

#### 🔴 TP · CRITICAL · Server-Side Template Injection: bác sĩ tự viết template Jinja2 chạy trên Environment không sandbox — `app/medicare/record/printing.py:97`

CWE-1336 · OWASP A05 · độ tin cậy 0.93 · nguồn: agent

**Phân tích:** Nội dung mẫu do bác sĩ nhập (body: Form) được lưu rồi biên dịch bằng `_env.from_string(body)` với `Environment(autoescape=True)` thông thường (không phải SandboxedEnvironment). validate() chỉ kiểm tra cú pháp và độ dài. Jinja2 cho phép truy cập thuộc tính dunder (ví dụ `{{ patient.__class__.__init__.__globals__ }}` hay `cycler.__init__.__globals__.os.popen(...)`), nên tài khoản bác sĩ (hoặc phiên bị chiếm) có thể thực thi mã tùy ý trên server, đọc secret, DB, toàn bộ dữ liệu bệnh án.

**Kịch bản khai thác:** Bác sĩ lưu mẫu chứa `{{ cycler.__init__.__globals__.os.popen('id').read() }}` tại POST /account/print-template, rồi mở /records/{id}/print: lệnh chạy trên server với quyền của ứng dụng.

**Đề xuất sửa:** Trong app/medicare/record/printing.py dùng jinja2.sandbox.SandboxedEnvironment (hoặc ImmutableSandboxedEnvironment) với autoescape=True cho cả validate() và render_slip(); chỉ truyền dict/giá trị thuần như _context hiện có. Cân nhắc thay Jinja bằng cơ chế thay thế biến đơn giản (whitelist placeholder) và bắt lỗi SecurityError/runtime khi render để không trả 500.

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/slip.html:17`

CWE-79 · OWASP A05 · độ tin cậy 0.85 · nguồn: semgrep

**Phân tích:** `{{ slip | safe }}` chèn HTML do template của bác sĩ sinh ra; template là HTML tự do (kể cả <script>) do người dùng nhập và không được làm sạch, nên XSS lưu trữ thực sự (script chạy trong origin của ứng dụng, có thể dùng cho trang in mà bệnh nhân khác cũng mở nếu mẫu được dùng chung/bị mở rộng). Ngoài ra nó đi cùng lỗi SSTI.

**Đề xuất sửa:** Không dùng |safe trên HTML do người dùng soạn: làm sạch đầu ra bằng allowlist (ví dụ bleach/nh3 chỉ cho thẻ và style an toàn) trước khi render, hoặc chỉ cho sửa các trường văn bản/escape toàn bộ; thêm CSP chặn script inline cho route /records/{id}/print.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Tìm trong repo không có X-Frame-Options hay frame-ancestors nào; ứng dụng thiếu header chống clickjacking toàn cục. | Thêm middleware security headers toàn cục trong ứng dụng FastAPI: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'). |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có Content-Security-Policy ở đâu trong repo; đặc biệt đáng lo vì trang in chèn HTML do người dùng soạn. | Thêm CSP chặt (default-src 'self', không cho script inline) trong middleware toàn cục. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu nosniff toàn cục. | Thêm X-Content-Type-Options: nosniff trong middleware toàn cục. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Repo không đặt X-Content-Type-Options: nosniff ở đâu. | Thêm X-Content-Type-Options: nosniff vào middleware security headers toàn cục. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 42.4 s · 17 lần gọi LLM · 16 lần gọi công cụ · 108516 token vào / 6040 token ra · ≈ $0.1569 · chạm giới hạn: không</sub>
