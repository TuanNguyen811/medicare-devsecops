<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f923a00`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Bypass khóa tài khoản/brute-force mật khẩu qua cookie remember-me của bất kỳ người dùng nào | `app/medicare/common/auth.py:54` | 0.90 |
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

#### 🔴 TP · HIGH · Bypass khóa tài khoản/brute-force mật khẩu qua cookie remember-me của bất kỳ người dùng nào — `app/medicare/common/auth.py:54`

CWE-307 · OWASP A07 · vi phạm R-07 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** login() gọi authenticate(..., remembered_device=remember.is_remembered_device(...)). Hàm này chỉ kiểm tra cookie chứa token hợp lệ của BẤT KỲ người dùng nào, không gắn với username đang đăng nhập. Khi remembered_device=True, authenticate bỏ qua kiểm tra locked_until và không tăng failed_login_count, nên không còn giới hạn số lần đoán mật khẩu và tài khoản đang bị khóa vẫn được đăng nhập nếu đoán đúng. Kẻ tấn công chỉ cần một tài khoản hợp lệ có tick "Ghi nhớ" để lấy cookie.

**Kịch bản khai thác:** Kẻ tấn công đăng nhập tài khoản của mình với remember_me=on, lấy cookie medicare_remember, rồi gửi hàng loạt POST /login với cookie này cho username nạn nhân. Không có khóa và không đếm lần sai, nên brute-force không giới hạn; tài khoản đã bị khóa vẫn đăng nhập được khi đoán trúng.

**Đề xuất sửa:** Xóa tham số remembered_device khỏi authenticate() và is_remembered_device khỏi login(); luôn áp dụng khóa 15 phút và đếm failed_login_count (R-07) cho mọi request. Nếu cần nới lỏng cho thiết bị tin cậy thì phải gắn token với đúng user_id của username đang đăng nhập, và vẫn không được bỏ qua khóa.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không có header X-Frame-Options/frame-ancestors; main.py chỉ có middleware Session, lỗi và metrics.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong toàn repo; trang /login dễ bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware chung trong main.py đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware chung trong main.py đặt CSP chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware chung trong main.py đặt CSP chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware chung trong main.py đặt CSP chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware chung trong main.py đặt CSP chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware chung trong main.py đặt CSP chặt.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu nosniff trên toàn ứng dụng.

**Đề xuất sửa:** Middleware chung trong main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff trên toàn ứng dụng, kể cả /health.

**Đề xuất sửa:** Middleware chung trong main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung trong main.py đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 43.6 s · 16 lần gọi LLM · 15 lần gọi công cụ · 96202 token vào / 5082 token ra · ≈ $0.0858 · chạm giới hạn: không</sub>
