<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `2b78fd1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Fail-open trong get_current_user: shift không hợp lệ vô hiệu hóa kiểm tra hết hạn/thu hồi session | `app/medicare/common/auth.py:112` | 0.93 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Fail-open trong get_current_user: shift không hợp lệ vô hiệu hóa kiểm tra hết hạn/thu hồi session — `app/medicare/common/auth.py:112`

CWE-636 · OWASP A10 · vi phạm R-08 · độ tin cậy 0.93 · nguồn: agent

**Phân tích:** Tham số form `shift` không được kiểm tra allowlist và được lưu vào session. `_max_age` dùng `SHIFT_MAX_AGE[...]` nên giá trị lạ gây KeyError. `get_current_user` bắt mọi Exception rồi fail-open: lấy user từ session mà bỏ qua kiểm tra `iat`, `is_active` và `session_version`. Kẻ tấn công đăng nhập với shift=x sẽ có session không bao giờ hết hạn, không bị thu hồi khi đổi mật khẩu/khóa tài khoản. Bệnh nhân cũng bị ảnh hưởng vì start_session lưu shift ban đầu chỉ khi không phải PATIENT, nhưng với staff thì đủ nghiêm trọng.

**Kịch bản khai thác:** Nhân viên (hoặc kẻ có cookie đánh cắp) đăng nhập POST /login với shift=bogus. Mọi request sau đó gây KeyError, bị nuốt, session luôn hợp lệ vĩnh viễn, kể cả sau revoke_sessions hoặc khi tài khoản bị khóa is_active=False.

**Đề xuất sửa:** Trong auth/router.py login, kiểm tra `shift` theo allowlist (khóa của SHIFT_MAX_AGE), giá trị lạ thì dùng DEFAULT_SHIFT hoặc trả lỗi. Trong _max_age dùng SHIFT_MAX_AGE.get(..., None). Bỏ khối `except Exception` fail-open trong get_current_user: khi lỗi phải fail-closed (clear session, raise LoginRequired) hoặc trả 500, không bao giờ bỏ qua kiểm tra iat/sv/is_active.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay CSP frame-ancestors ở bất kỳ đâu trong mã; ứng dụng không đặt header chống clickjacking.

**Đề xuất sửa:** Thêm middleware đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong mã (search không có kết quả).

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY / frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong mã.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong mã.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self') qua middleware bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong mã.

**Đề xuất sửa:** Thêm CSP qua middleware bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong mã.

**Đề xuất sửa:** Thêm CSP qua middleware bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong mã.

**Đề xuất sửa:** Thêm CSP qua middleware bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong mã.

**Đề xuất sửa:** Middleware đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong mã.

**Đề xuất sửa:** Middleware đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 32.4 s · 15 lần gọi LLM · 14 lần gọi công cụ · 79685 token vào / 4503 token ra · ≈ $0.1132 · chạm giới hạn: không</sub>
