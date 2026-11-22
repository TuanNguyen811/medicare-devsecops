<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f923a00`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Cookie remember-me (do client kiểm soát) vô hiệu hóa cơ chế khóa tài khoản R-07 | `app/medicare/common/auth.py:54` | 0.90 |
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

#### 🔴 TP · HIGH · Cookie remember-me (do client kiểm soát) vô hiệu hóa cơ chế khóa tài khoản R-07 — `app/medicare/common/auth.py:54`

CWE-307 · OWASP A07 · vi phạm R-07 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /login gọi authenticate(..., remembered_device=remember.is_remembered_device(db, request, now)). Hàm này trả True khi cookie medicare_remember khớp với BẤT KỲ RememberToken còn hạn của user nào, không gắn với username đang đăng nhập. Khi remembered_device=True, authenticate bỏ qua kiểm tra locked_until và không tăng failed_login_count khi sai mật khẩu. Kẻ tấn công chỉ cần một tài khoản hợp lệ, chọn "Ghi nhớ đăng nhập" để lấy token hợp lệ, rồi gửi cookie đó kèm mọi lần đoán mật khẩu của tài khoản nạn nhân. Brute-force không giới hạn, và tài khoản đang bị khóa vẫn đăng nhập được.

**Kịch bản khai thác:** Kẻ tấn công đăng nhập bằng tài khoản của mình kèm remember_me để nhận token. Sau đó gửi hàng loạt POST /login với username của bác sĩ và cookie medicare_remember đó. Bộ đếm failed_login_count không tăng và khóa không áp dụng, nên có thể dò mật khẩu không giới hạn.

**Đề xuất sửa:** Xóa tham số remembered_device khỏi authenticate() trong app/medicare/common/auth.py và xóa is_remembered_device trong app/medicare/auth/remember.py. Luôn áp dụng kiểm tra khóa và đếm lần sai (R-07) cho mọi lần đăng nhập bằng mật khẩu. Nếu cần nới lỏng cho máy đã nhớ, phải gắn token với đúng user đang đăng nhập và vẫn tính lần sai.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware hay cấu hình nào trong repo đặt X-Frame-Options hoặc frame-ancestors; main.py chỉ có CatchAllErrors, Session và Metrics middleware.

**Đề xuất sửa:** Thêm một middleware trong app/medicare/main.py đặt X-Frame-Options: DENY, X-Content-Type-Options: nosniff và Content-Security-Policy (có frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào được đặt trong repo, trang /login cũng vậy.

**Đề xuất sửa:** Dùng chung middleware security headers trong app/medicare/main.py (X-Frame-Options: DENY và CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm header Content-Security-Policy trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm header Content-Security-Policy trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm header Content-Security-Policy trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm header Content-Security-Policy trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm header Content-Security-Policy trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options nào được đặt trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options nào được đặt trong repo, kể cả cho /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options nào được đặt trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 56.9 s · 27 lần gọi LLM · 15 lần gọi công cụ · 113488 token vào / 9441 token ra · ≈ $0.1944 · chạm giới hạn: không</sub>
