<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f923a00`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Cookie remember-me bỏ qua khóa tài khoản và bộ đếm đăng nhập sai (R-07) | `app/medicare/common/auth.py:54` | 0.90 |
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

#### 🔴 TP · HIGH · Cookie remember-me bỏ qua khóa tài khoản và bộ đếm đăng nhập sai (R-07) — `app/medicare/common/auth.py:54`

CWE-307 · OWASP A07 · vi phạm R-07 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** authenticate() nhận remembered_device do client điều khiển (chỉ cần cookie medicare_remember hợp lệ về hình thức). Khi True: tài khoản đang bị khóa vẫn được thử mật khẩu và không tăng failed_login_count, nên không bao giờ khóa. Token là bất kỳ token nào còn hạn (của bất kỳ user nào), không gắn với username đăng nhập. Kẻ tấn công có một token hợp lệ (ví dụ chính tài khoản của hắn bật remember-me) có thể brute-force mật khẩu của tài khoản khác không giới hạn.

**Kịch bản khai thác:** Kẻ tấn công đăng nhập tài khoản của mình với remember_me, lấy cookie, rồi gửi hàng loạt POST /login kèm cookie đó với username nạn nhân và danh sách mật khẩu: không bị khóa, không đếm lần sai.

**Đề xuất sửa:** Xóa tham số remembered_device khỏi authenticate() và is_remembered_device khỏi login(): luôn áp dụng khóa 5 lần/15 phút và đếm lần sai cho mọi trình duyệt. Nếu cần ngoại lệ, phải gắn token với đúng user đang đăng nhập và không bao giờ bỏ qua khóa.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không tìm thấy nơi nào trong repo đặt X-Frame-Options hay CSP frame-ancestors.

**Đề xuất sửa:** Thêm middleware toàn cục trong app factory đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang login bị ảnh hưởng.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt (default-src 'self').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 34.2 s · 15 lần gọi LLM · 14 lần gọi công cụ · 77427 token vào / 5134 token ra · ≈ $0.0819 · chạm giới hạn: không</sub>
