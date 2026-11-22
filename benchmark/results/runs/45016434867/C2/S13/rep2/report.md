<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `2b78fd1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Fail-open trong get_current_user: shift không hợp lệ làm mất kiểm tra hết hạn, thu hồi phiên và is_active | `app/medicare/common/auth.py:112` | 0.95 |
| 🔴 TP | MEDIUM | agent | Client tự chọn thời hạn phiên 12h/24h cho mọi vai trò nhân viên | `app/medicare/auth/router.py:35` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.85 |

### Chi tiết

#### 🔴 TP · CRITICAL · Fail-open trong get_current_user: shift không hợp lệ làm mất kiểm tra hết hạn, thu hồi phiên và is_active — `app/medicare/common/auth.py:112`

CWE-636 · OWASP A10 · vi phạm R-08 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Tham số form `shift` do client gửi được lưu nguyên vào session mà không đối chiếu allowlist (router.py -> start_session). Khi shift không nằm trong SHIFT_MAX_AGE, `_max_age` ném KeyError. `get_current_user` bắt mọi Exception rồi dùng nhánh dự phòng chỉ gọi db.get(User, user_id): bỏ qua hết hạn tuyệt đối, kiểm tra session_version (revoke_sessions, đặt lại mật khẩu R-18) và is_active (tài khoản bị khóa). Phiên trở nên vĩnh viễn và không thể thu hồi. Ngoài ra bất kỳ lỗi DB nào trong kiểm tra cũng bị fail-open.

**Kịch bản khai thác:** Nhân viên (hoặc kẻ có thông tin đăng nhập) gửi POST /login với shift=x. Session mang shift="x", mọi request sau đó gây KeyError và rơi vào nhánh dự phòng. Phiên không bao giờ hết hạn, vẫn dùng được sau khi admin khóa tài khoản hoặc revoke_sessions.</exploit_scenario>
<parameter name="fix">{"description":"Trong start_session (hoặc router login) kiểm tra shift nằm trong SHIFT_MAX_AGE, nếu không thì dùng DEFAULT_SHIFT hoặc trả 422. Trong _max_age dùng SHIFT_MAX_AGE.get(..., None) để giá trị lạ về mặc định. Trong get_current_user bỏ nhánh except fail-open: khi kiểm tra lỗi phải fail-closed (clear session, raise LoginRequired; hoặc để lỗi 500 xử lý bởi CatchAllErrorsMiddleware), không được dùng user mà chưa kiểm tra sv, is_active và iat."}

#### 🔴 TP · MEDIUM · Client tự chọn thời hạn phiên 12h/24h cho mọi vai trò nhân viên — `app/medicare/auth/router.py:35`

CWE-613 · OWASP A06 · vi phạm R-08 · độ tin cậy 0.70 · nguồn: agent

**Phân tích:** Thời hạn phiên tuyệt đối được quyết định bởi giá trị form do người dùng gửi, không dựa trên ca trực được cấp phía server. Bất kỳ nhân viên nào (kể cả lễ tân, admin) có thể chọn 24h, làm tăng cửa sổ bị đánh cắp phiên với dữ liệu y tế.

**Đề xuất sửa:** Không tin tham số client: xác định thời hạn phiên phía server theo vai trò hoặc lịch trực được gán cho tài khoản (chỉ DOCTOR/NURSE có ca), hoặc giữ thời hạn mặc định và dùng cơ chế gia hạn/đăng nhập lại. Nếu giữ lựa chọn, kiểm tra allowlist và giới hạn theo vai trò.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay frame-ancestors ở đâu trong repo; main.py chỉ có middleware lỗi, session, metrics. Ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking; không có middleware nào đặt header bảo mật.

**Đề xuất sửa:** Dùng middleware security headers chung trong main.py: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff và không có CSP trong toàn repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware trong main.py đặt X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng (tìm kiếm toàn repo không thấy).

**Đề xuất sửa:** Middleware security headers chung trong main.py đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Middleware security headers chung trong main.py đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Middleware security headers chung trong main.py đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Middleware security headers chung trong main.py đặt Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options trong ứng dụng.

**Đề xuất sửa:** Middleware trong main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options trong ứng dụng, kể cả /health.

**Đề xuất sửa:** Middleware trong main.py đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 42.6 s · 18 lần gọi LLM · 17 lần gọi công cụ · 103878 token vào / 5929 token ra · ≈ $0.1062 · chạm giới hạn: không</sub>
