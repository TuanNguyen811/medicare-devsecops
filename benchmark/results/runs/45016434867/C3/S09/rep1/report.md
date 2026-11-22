<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `447aa04`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B310 (bandit) | `app/medicare/record/lab.py:39` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |

### Chi tiết

#### 🔴 TP · HIGH · B310 (bandit) — `app/medicare/record/lab.py:39`

CWE-918 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** download() nhận URL do bác sĩ nhập và gọi urllib.request.urlopen chỉ sau khi kiểm tra scheme http/https và có hostname. Không có allowlist host (vi phạm R-14), không chặn IP nội bộ/loopback/link-local (ví dụ metadata 169.254.169.254, dịch vụ nội bộ, DB), và urlopen mặc định tự theo redirect nên có thể bị chuyển sang địa chỉ nội bộ. Đây là SSRF. Việc kiểm tra content-type chỉ chặn việc lưu phản hồi sai loại; request vẫn được gửi (blind SSRF), và kẻ tấn công kiểm soát một server nội bộ/ngoài trả PDF/PNG vẫn đọc lại được nội dung qua /lab-results/{id}. Test chỉ dùng URL LIS hợp lệ, không có test cho host nội bộ.

**Kịch bản khai thác:** Một tài khoản bác sĩ (hoặc phiên bị chiếm) gửi url=http://169.254.169.254/latest/meta-data/... hoặc http://internal-service:8080/..., hoặc một URL ngoài redirect (302) về địa chỉ nội bộ. Server MediCare gửi request từ bên trong mạng, dò quét cổng/dịch vụ nội bộ qua khác biệt thông báo lỗi và thời gian, hoặc lấy dữ liệu nếu đích trả content-type pdf/png.

**Đề xuất sửa:** Trong lab.download(): đối chiếu hostname với allowlist cấu hình qua biến môi trường (ví dụ chỉ lis.medicare.local) trước khi gọi urlopen (R-14). Yêu cầu https. Phân giải DNS và từ chối IP loopback/private/link-local/reserved, rồi kết nối đúng IP đã kiểm tra để tránh DNS rebinding. Tắt hoặc kiểm tra lại từng redirect bằng opener tùy chỉnh (HTTPRedirectHandler) áp cùng allowlist. Thêm test cho host nội bộ, redirect và URL ngoài allowlist.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP quan sát thực tế phản hồi thiếu X-Frame-Options/frame-ancestors. Không có bằng chứng middleware đặt security header toàn cục (route tải kết quả phải tự đặt nosniff, cho thấy không có cơ chế chung). Ứng dụng có form thay đổi dữ liệu y tế nên clickjacking có ý nghĩa.

**Đề xuất sửa:** Thêm middleware toàn cục trong app factory (app/medicare) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; trang đăng nhập là mục tiêu UI-redress phổ biến. Cùng nguyên nhân gốc với F2: thiếu middleware security header.

**Đề xuất sửa:** Sửa cùng chỗ với F2: middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Phản hồi thiếu Content-Security-Policy; không thấy cấu hình CSP toàn cục. Là lỗi cấu hình chung của ứng dụng, không riêng route này.

**Đề xuất sửa:** Thêm CSP toàn cục qua middleware (default-src 'self', frame-ancestors 'none'), điều chỉnh cho tài nguyên Bootstrap đang dùng.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F7: không có CSP toàn cục.

**Đề xuất sửa:** Sửa cùng middleware CSP toàn cục như F7.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F7: không có CSP toàn cục.

**Đề xuất sửa:** Sửa cùng middleware CSP toàn cục như F7.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F7: không có CSP toàn cục.

**Đề xuất sửa:** Sửa cùng middleware CSP toàn cục như F7.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F7: không có CSP toàn cục.

**Đề xuất sửa:** Sửa cùng middleware CSP toàn cục như F7.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Trang / thiếu X-Content-Type-Options; cùng nguyên nhân với F6.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** /health thiếu X-Content-Type-Options; rủi ro rất thấp (endpoint không chứa nội dung người dùng) nhưng cùng nguyên nhân với F6, sẽ được sửa bằng middleware chung.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff, áp dụng cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Phản hồi /login thiếu X-Content-Type-Options: nosniff; chỉ route tải kết quả xét nghiệm tự đặt header này. Nguyên nhân là thiếu middleware chung. Rủi ro thấp nhưng sửa dễ.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff cho mọi phản hồi.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 40.1 s · 13 lần gọi LLM · 12 lần gọi công cụ · 63871 token vào / 6040 token ra · ≈ $0.1949 · chạm giới hạn: không</sub>
