<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `447aa04`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B310 (bandit) | `app/medicare/record/lab.py:39` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · B310 (bandit) — `app/medicare/record/lab.py:39`

CWE-918 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** download() chỉ kiểm tra scheme http/https và có hostname, không có allowlist host (vi phạm R-14). urlopen cũng tự động theo redirect. Bác sĩ có thể khiến server gọi tới địa chỉ nội bộ (metadata cloud, dịch vụ nội bộ, localhost) — SSRF. Nội dung phản hồi được lưu và có thể tải lại nếu là PDF/ảnh; lỗi/thời gian phản hồi còn cho phép dò mạng nội bộ.

**Kịch bản khai thác:** Bác sĩ (hoặc tài khoản bác sĩ bị chiếm) gửi url=http://169.254.169.254/... hoặc http://internal-host:port/, hoặc URL ngoài redirect 302 tới địa chỉ nội bộ; server gọi tới đó và lộ thông tin/dò mạng nội bộ.

**Đề xuất sửa:** Trong lab.download(): đối chiếu hostname với allowlist cấu hình (ví dụ lis.medicare.local) trước khi gọi; chỉ cho phép https; phân giải DNS và chặn IP private/loopback/link-local; tắt hoặc kiểm tra lại mỗi lần redirect (opener với HTTPRedirectHandler tùy biến) và dùng IP đã kiểm tra khi kết nối.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy middleware nào đặt X-Frame-Options hay frame-ancestors; ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware toàn ứng dụng (app factory/main) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong code (tìm toàn repo); trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware toàn ứng dụng đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng đặt Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware đặt nosniff toàn cục.

**Đề xuất sửa:** Middleware toàn ứng dụng đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware đặt nosniff toàn cục; /health cũng thiếu.

**Đề xuất sửa:** Middleware toàn ứng dụng đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Chỉ endpoint tải lab-result đặt nosniff (router.py:152); các trang khác như /login không có X-Content-Type-Options, không có middleware chung.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware toàn ứng dụng đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 38.3 s · 16 lần gọi LLM · 15 lần gọi công cụ · 76999 token vào / 5252 token ra · ≈ $0.0872 · chạm giới hạn: không</sub>
