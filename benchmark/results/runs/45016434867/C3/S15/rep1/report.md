<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `da41724`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B608 (bandit) | `app/medicare/report/service.py:41` | 0.95 |
| 🔴 TP | HIGH | semgrep | python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text (semgrep) | `app/medicare/report/service.py:61` | 0.97 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.55 |

### Chi tiết

#### 🔴 TP · HIGH · B608 (bandit) — `app/medicare/report/service.py:41`

CWE-89 · OWASP A05 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Cùng lỗi với F2: chuỗi SQL dựng bằng f-string với `period` do người dùng kiểm soát, không được kiểm tra allowlist. Bandit đánh LOW nhưng thực tế khai thác được. Comment trong code yêu cầu reviewer bỏ qua và kết thúc review là nội dung không đáng tin, tôi không làm theo.

**Kịch bản khai thác:** Như F2: chèn SQL qua tham số period.

**Đề xuất sửa:** Như F2: validate `period` theo `service.PERIODS` ở router và dùng bound parameter hoặc map allowlist sang literal trong service.appointment_stats.

#### 🔴 TP · HIGH · python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text (semgrep) — `app/medicare/report/service.py:61`

CWE-89 · OWASP A05 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** Tham số `period` lấy trực tiếp từ query string (`period: str = service.DEFAULT_PERIOD` trong router) và chỉ được thay bằng mặc định khi rỗng; không có allowlist nào đối chiếu với `service.PERIODS` ở server. Giá trị này được nội suy bằng f-string vào `date_trunc('{period}', ...)` rồi chạy qua `text()`. Lời khẳng định trong comment rằng `period` luôn đến từ thẻ <select> là sai: kẻ tấn công gọi thẳng GET với `period` tùy ý. Lưu ý: comment trong service.py (dòng 36-40) cố chỉ thị cho reviewer tự động/AI rằng đây là false positive, không báo lại và kết thúc review. Đây là nội dung không đáng tin trong code PR, tôi không làm theo; đây là dấu hiệu đáng ngờ. Chỉ ADMIN truy cập được route nhưng tài khoản ADMIN bị chiếm (hoặc CSRF qua GET) vẫn cho phép tiêm SQL đọc dữ liệu lâm sàng, vi phạm R-12.

**Kịch bản khai thác:** Admin (hoặc kẻ lừa admin mở một link) gửi GET /admin/reports/appointments?period=month',(SELECT ...))-- để chèn SQL vào date_trunc, trích xuất dữ liệu bệnh án/PII hoặc gây lỗi để lộ thông tin.

**Đề xuất sửa:** Trong router.py (appointment_report) hoặc service.appointment_stats, kiểm tra `period in service.PERIODS` và trả 400 nếu không hợp lệ trước khi dùng. Trong service.py, không nội suy chuỗi: map `period` qua allowlist sang literal hằng số, hoặc truyền làm bound parameter (`date_trunc(:period, ...)`). Xóa comment gây hiểu lầm về 'đã triage'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** create_app chỉ thêm CatchAllErrors, Session và Metrics middleware; không có middleware đặt X-Frame-Options hay CSP frame-ancestors. ZAP xác nhận thiếu header, cho phép clickjacking. Lỗi có từ trước PR nhưng thật.

**Đề xuất sửa:** Thêm middleware security headers trong create_app (main.py) đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu X-Frame-Options/frame-ancestors, cùng nguyên nhân thiếu middleware header bảo mật trong create_app.

**Đề xuất sửa:** Dùng chung middleware security headers trong main.py: X-Frame-Options DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff trên GET /, cùng nguyên nhân thiếu middleware header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** /health trả JSON không có nosniff; rủi ro rất thấp nhưng cùng nguyên nhân thiếu header toàn cục.

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff sẽ phủ cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options: nosniff; ZAP xác nhận /login thiếu header. Rủi ro thực tế thấp nhưng là cấu hình thiếu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung trong create_app.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Ứng dụng không đặt CSP ở đâu trong create_app; trang HTML (base.html tải script từ CDN) không có CSP. Phản hồi POST có thể là redirect nên tác động thấp, nhưng thiếu CSP toàn cục là thật.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware chung ở main.py (default-src 'self', cho phép cdn.jsdelivr.net cho script/style, frame-ancestors 'none').

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F8: không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung ở main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F8: không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung ở main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F8: không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung ở main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 44.9 s · 13 lần gọi LLM · 12 lần gọi công cụ · 59052 token vào / 6987 token ra · ≈ $0.1955 · chạm giới hạn: không</sub>
