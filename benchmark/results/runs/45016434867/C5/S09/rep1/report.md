<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `447aa04`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B310 (bandit) | `app/medicare/record/lab.py:39` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · B310 (bandit) — `app/medicare/record/lab.py:39`

CWE-918 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** download() trong lab.py chỉ kiểm tra scheme http/https rồi gọi urllib.request.urlopen với URL do bác sĩ nhập, không có allowlist host. Đây là SSRF: có thể trỏ tới 169.254.169.254, localhost hoặc dịch vụ nội bộ. urlopen còn tự theo redirect nên có thể vượt qua kiểm tra. Request vẫn được gửi đi dù nội dung bị loại (blind SSRF). Vi phạm R-14.

**Kịch bản khai thác:** Bác sĩ phụ trách (hoặc tài khoản bị chiếm) nhập url=http://169.254.169.254/... hoặc http://dich-vu-noi-bo:port/ để dò mạng nội bộ, hoặc dùng URL ngoài redirect về địa chỉ nội bộ. Thông báo lỗi và thời gian phản hồi khác nhau cho phép quét cổng.

**Đề xuất sửa:** Trong lab.download(): đối chiếu hostname và port với allowlist host của LIS lấy từ cấu hình (biến môi trường), chỉ cho phép https. Resolve DNS và từ chối IP private/loopback/link-local. Tắt theo redirect (opener với HTTPRedirectHandler tùy chỉnh) hoặc kiểm tra lại allowlist ở mỗi redirect. Giữ giới hạn kích thước và timeout.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors (search_code chỉ thấy nosniff ở một route). Ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking; không có middleware đặt header bảo mật toàn cục.

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Frame-Options: DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong code (search_code không thấy Content-Security-Policy).

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong code ứng dụng.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong code ứng dụng.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong code ứng dụng.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong code ứng dụng.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff ở GET /, không có middleware toàn cục.

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu nosniff ở /health, không có middleware toàn cục.

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Chỉ route tải lab-result đặt nosniff; các trang khác như /login thiếu X-Content-Type-Options, không có middleware toàn cục.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 53.2 s · 27 lần gọi LLM · 15 lần gọi công cụ · 118482 token vào / 8885 token ra · ≈ $0.2031 · chạm giới hạn: không</sub>
