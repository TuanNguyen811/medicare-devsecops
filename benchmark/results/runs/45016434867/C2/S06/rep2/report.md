<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `b6844e9`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/detail.html:29` | 0.97 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/detail.html:29`

CWE-79 · OWASP A05 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** Trường `note.body` do người dùng gửi lên được render bằng `| safe`. `service.add_note` chỉ strip và kiểm tra độ dài, không làm sạch HTML. Việc "định dạng" chỉ thực hiện ở client (JS), nên có thể bị bỏ qua bằng cách POST trực tiếp. Đây là stored XSS: script chạy trong phiên của bệnh nhân, y tá và bác sĩ khác khi xem bệnh án.

**Kịch bản khai thác:** Bác sĩ phụ trách (hoặc kẻ chiếm tài khoản bác sĩ) POST body `<img src=x onerror=...>`. Khi bệnh nhân hoặc bác sĩ khác mở /records/{id}, script chạy và có thể đọc dữ liệu y tế hoặc gửi request kèm CSRF token.

**Đề xuất sửa:** Bỏ `| safe` trong detail.html để Jinja tự escape, hoặc làm sạch ở server trước khi lưu trong `record/service.py::add_note` bằng allowlist thẻ (b, i, u, ul, li, p, br) qua thư viện như nh3 hoặc bleach, không cho phép thuộc tính. Không tin sanitize phía client trong rich-note.js.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong code không thấy X-Frame-Options hay CSP frame-ancestors nào; main.py chỉ có các middleware lỗi, session và metrics. Ứng dụng có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py để đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong code; trang /login có thể bị nhúng vào iframe.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py để đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong code. Thiếu CSP làm mất lớp phòng thủ chiều sâu chống XSS, đặc biệt khi PR này có stored XSS.

**Đề xuất sửa:** Thêm CSP (default-src 'self'; script-src 'self'; frame-ancestors 'none') qua middleware security headers trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong code.

**Đề xuất sửa:** Thêm CSP qua middleware security headers trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong code.

**Đề xuất sửa:** Thêm CSP qua middleware security headers trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong code.

**Đề xuất sửa:** Thêm CSP qua middleware security headers trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff, không có middleware nào đặt header này.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py để đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff; không có middleware nào đặt header này. Với /health rủi ro thấp, nhưng cùng cách sửa.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py để đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Code không đặt X-Content-Type-Options: nosniff ở bất kỳ đâu (search không có kết quả).

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py để đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 33.6 s · 14 lần gọi LLM · 13 lần gọi công cụ · 53838 token vào / 4664 token ra · ≈ $0.0737 · chạm giới hạn: không</sub>
