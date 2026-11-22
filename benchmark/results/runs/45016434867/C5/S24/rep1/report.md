<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f923a00`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Cookie remember-me (không gắn thiết bị) bỏ qua khóa tài khoản và đếm sai mật khẩu | `app/medicare/common/auth.py:54` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Cookie remember-me (không gắn thiết bị) bỏ qua khóa tài khoản và đếm sai mật khẩu — `app/medicare/common/auth.py:54`

CWE-307 · OWASP A07 · vi phạm R-07 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** authenticate() nhận remembered_device do client điều khiển: chỉ cần cookie medicare_remember hợp lệ (bất kỳ token nào còn hạn, của bất kỳ user nào, vì is_remembered_device không gắn token với username đang đăng nhập). Khi đó tài khoản bị khóa vẫn được thử mật khẩu và sai mật khẩu không tăng failed_login_count, nên brute-force không giới hạn. Kẻ tấn công chỉ cần một remember token hợp lệ (tự đăng nhập bằng tài khoản của mình có tích 'ghi nhớ') để vô hiệu hóa R-07 cho mọi tài khoản.

**Kịch bản khai thác:** Kẻ tấn công có tài khoản bệnh nhân, đăng nhập với remember_me để lấy cookie, rồi gửi hàng loạt POST /login kèm cookie này với username của bác sĩ và danh sách mật khẩu; không bị khóa, không bị đếm lỗi.

**Đề xuất sửa:** Xóa tham số remembered_device khỏi authenticate() trong app/medicare/common/auth.py và router.login: luôn áp dụng khóa 15 phút và đếm failed_login_count như R-07 bất kể cookie. Không dùng cookie do client gửi để miễn trừ kiểm soát brute-force.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Frame-Options hay frame-ancestors ở đâu trong mã; main.py chỉ thêm middleware lỗi/session/metrics.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking; không header nào được đặt trong mã.

**Đề xuất sửa:** Dùng middleware security headers chung trong app/medicare/main.py (X-Frame-Options DENY / frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong mã.

**Đề xuất sửa:** Middleware security headers chung trong main.py đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong mã.

**Đề xuất sửa:** Middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong mã.

**Đề xuất sửa:** Middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong mã.

**Đề xuất sửa:** Middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong mã.

**Đề xuất sửa:** Middleware CSP chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu nosniff trên mọi response.

**Đề xuất sửa:** Middleware security headers chung trong main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff trên /health; cùng nguyên nhân gốc, không có middleware đặt header.

**Đề xuất sửa:** Middleware security headers chung trong main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff trong mã.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers chung trong main.py đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 52.7 s · 26 lần gọi LLM · 15 lần gọi công cụ · 144489 token vào / 7988 token ra · ≈ $0.1868 · chạm giới hạn: không</sub>
