<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `743d5ee`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🟡 NEEDS_REVIEW | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/announcement/admin.html:37` | 0.85 |
| 🟢 FP | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/home.html:20` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** create_app không đăng ký middleware nào thêm header bảo mật, nên phản hồi thiếu X-Frame-Options / frame-ancestors; trang có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py (create_app) đặt `X-Frame-Options: DENY` và CSP `frame-ancestors 'none'` cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login cũng thiếu chống clickjacking vì không có middleware header bảo mật toàn cục.

**Đề xuất sửa:** Dùng chung middleware header bảo mật trong main.py: `X-Frame-Options: DENY` và `frame-ancestors 'none'`.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy; do có render HTML thông báo, CSP là lớp phòng thủ chiều sâu chống XSS.

**Đề xuất sửa:** Thêm CSP trong middleware ở main.py (default-src 'self', cho phép cdn.jsdelivr.net cho bootstrap, frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục, ảnh hưởng mọi route.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục, ảnh hưởng mọi route.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục, ảnh hưởng mọi route.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu nosniff do không có middleware header bảo mật.

**Đề xuất sửa:** Thêm `X-Content-Type-Options: nosniff` trong middleware toàn cục ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** /health trả JSON không có nosniff; rủi ro thấp, được xử lý chung bởi middleware header.

**Đề xuất sửa:** Middleware header toàn cục trong main.py thêm `X-Content-Type-Options: nosniff` cho mọi phản hồi, gồm /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options: nosniff do thiếu middleware header toàn cục.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm `X-Content-Type-Options: nosniff` trong middleware header bảo mật ở main.py (create_app).

#### 🟡 NEEDS_REVIEW · LOW · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/announcement/admin.html:37`

CWE-79 · độ tin cậy 0.85 · nguồn: semgrep

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] `body_html | safe` chỉ render trường đã được làm sạch bằng bleach khi ghi (service.create → clean_body). Allowlist thẻ chặt (không có script/img/style), chỉ cho phép thuộc tính href/title trên thẻ a, giao thức chỉ http/https/mailto (chặn javascript:). Chỉ ADMIN tạo được thông báo, kèm CSRF; không có đường ghi nào khác vào body_html. Tiêu đề và tên tác giả vẫn được Jinja tự escape.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **security.semgrep.medicare.jinja-safe-filter (semgrep)** — `app/medicare/templates/home.html:20`: Cùng nguyên nhân với F1: body_html trên trang chủ chỉ lấy từ DB, đã qua bleach.clean với allowlist chặt và protocol allowlist trước khi lưu. Chỉ ADMIN có đường ghi. Title được escape tự động.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 55.8 s · 3 lần gọi LLM · 12 lần gọi công cụ · 81781 token vào / 9495 token ra · ≈ $0.2827 · chạm giới hạn: không</sub>
