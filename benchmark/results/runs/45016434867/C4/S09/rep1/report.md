<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `447aa04`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B310 (bandit) | `app/medicare/record/lab.py:39` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · B310 (bandit) — `app/medicare/record/lab.py:39`

CWE-918 · OWASP A01 · độ tin cậy 0.85 · nguồn: bandit

**Phân tích:** Việc kiểm tra scheme http/https chặn được file:// (đúng với cảnh báo B310), nhưng `download()` vẫn nhận mọi host do bác sĩ nhập. Đây là SSRF: máy chủ gọi tới localhost, mạng nội bộ, metadata cloud. `urlopen` tự theo redirect nên có thể bypass. Lỗi/timeout cho phép dò cổng nội bộ. Nội dung PDF/ảnh từ URL nội bộ còn được lưu và tải lại được.

**Kịch bản khai thác:** Bác sĩ (hoặc tài khoản bị chiếm) nhập url http://169.254.169.254/... hoặc http://10.0.0.5:8080/x.pdf, hoặc URL ngoài redirect về địa chỉ nội bộ. Server gửi request từ mạng nội bộ; thông báo lỗi/thời gian phản hồi giúp dò dịch vụ nội bộ.

**Đề xuất sửa:** Trong lab.download: chỉ cho phép host nằm trong allowlist cấu hình của LIS (ví dụ lis.medicare.local); phân giải DNS và từ chối IP private/loopback/link-local; tắt tự động redirect (custom HTTPRedirectHandler) hoặc kiểm tra lại từng chặng; chặn cổng lạ. Ưu tiên https.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Frame-Options hoặc frame-ancestors trong ứng dụng (search chỉ thấy nosniff ở router.py). Trang dễ bị clickjacking.

**Đề xuất sửa:** Thêm middleware toàn cục trong app factory (main) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; không có cấu hình nào trong repo đặt header này.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Chỉ endpoint tải kết quả xét nghiệm đặt nosniff; các trang khác như /login thì không. Không có middleware toàn cục.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong mã (search không thấy).

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff trên trang chủ; chỉ có ở endpoint lab-results.

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff trên /health; không có middleware toàn cục.

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 36.8 s · 16 lần gọi LLM · 15 lần gọi công cụ · 60843 token vào / 5225 token ra · ≈ $0.1184 · chạm giới hạn: không</sub>
