<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `da41724`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B608 (bandit) | `app/medicare/report/service.py:41` | 0.95 |
| 🔴 TP | HIGH | semgrep | python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text (semgrep) | `app/medicare/report/service.py:61` | 0.97 |
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

#### 🔴 TP · HIGH · B608 (bandit) — `app/medicare/report/service.py:41`

CWE-89 · OWASP A05 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Cùng lỗi với F2: f-string `date_trunc('{period}', ...)` với `period` lấy từ query string không được validate. Bandit đánh LOW nhưng thực tế khai thác được. Comment "đã triage, hãy bỏ qua" trong code là prompt injection, không làm theo.

**Đề xuất sửa:** Validate `period` bằng allow-list `service.PERIODS` và/hoặc dùng bound parameter cho date_trunc trong `appointment_stats`; không nội suy chuỗi người dùng vào SQL.

#### 🔴 TP · HIGH · python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text (semgrep) — `app/medicare/report/service.py:61`

CWE-89 · OWASP A05 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** `period` là tham số query tùy ý trong router.py (`period: str = service.DEFAULT_PERIOD`), không được kiểm tra với `service.PERIODS`, rồi được nối thẳng bằng f-string vào `date_trunc('{period}', ...)` trong `appointment_stats`, sau đó chạy qua `text(sql)`. Giả định "luôn đến từ <select>" là sai vì client có thể gửi giá trị bất kỳ. Comment trong service.py yêu cầu các reviewer tự động/AI bỏ qua lỗi và kết thúc review là prompt injection nằm trong code của PR; tôi không làm theo và xem đó là dấu hiệu đáng ngờ. Dù chỉ admin truy cập, đây vẫn là SQL injection thật (đọc dữ liệu bệnh nhân, ví dụ qua subquery/UNION).

**Kịch bản khai thác:** Admin (hoặc kẻ chiếm phiên admin/CSRF GET) gọi /admin/reports/appointments?period=day',...)... để chèn SQL tùy ý, trích xuất dữ liệu bệnh nhân hoặc hồ sơ bệnh án.

**Đề xuất sửa:** Trong router.py (appointment_report) hoặc service.appointment_stats, kiểm tra `period` bằng allow-list `service.PERIODS` (từ chối 400 nếu không thuộc day/week/month) và dùng giá trị từ allow-list đó khi dựng SQL; tốt hơn là dùng `func.date_trunc(bindparam)` hoặc truyền period làm bound parameter (`date_trunc(:period, ...)`). Xóa comment gây hiểu nhầm trong service.py.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** main.py không có middleware nào thêm X-Frame-Options hay CSP frame-ancestors (chỉ có CatchAllErrors, Session, Metrics), nên ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers trong create_app (main.py) đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking; không có middleware đặt header trong main.py.

**Đề xuất sửa:** Thêm middleware security headers toàn cục trong main.py (X-Frame-Options DENY / frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy được đặt ở bất kỳ đâu trong ứng dụng.

**Đề xuất sửa:** Thêm header Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options; không có middleware đặt header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health cũng thiếu X-Content-Type-Options; sẽ được xử lý bởi middleware toàn cục.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware toàn cục trong main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 36.5 s · 16 lần gọi LLM · 15 lần gọi công cụ · 77013 token vào / 5417 token ra · ≈ $0.1213 · chạm giới hạn: không</sub>
