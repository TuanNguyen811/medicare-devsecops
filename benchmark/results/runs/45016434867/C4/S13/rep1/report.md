<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `2b78fd1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | get_current_user fail-open: lỗi khi kiểm tra phiên vẫn chấp nhận session | `app/medicare/common/auth.py:114` | 0.90 |
| 🔴 TP | MEDIUM | agent | Thời hạn phiên do client tự chọn qua tham số shift, không có kiểm soát phía server | `app/medicare/common/auth.py:73` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · get_current_user fail-open: lỗi khi kiểm tra phiên vẫn chấp nhận session — `app/medicare/common/auth.py:114`

CWE-636 · OWASP A10 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Trong get_current_user, khi _session_user ném exception, code bắt `except Exception` rồi lấy lại user chỉ từ user_id trong session, bỏ qua kiểm tra session_version, is_active và thời hạn tuyệt đối. Đây là fail-open: phiên đã bị thu hồi (revoke_sessions), tài khoản bị khóa hoặc phiên hết hạn vẫn được chấp nhận nếu gây được lỗi (ví dụ session['shift'] có giá trị lạ gây KeyError trong _max_age).

**Kịch bản khai thác:** Người dùng đã bị vô hiệu hóa hoặc bị revoke phiên, hoặc cookie hết hạn, gây lỗi trong _session_user (shift không hợp lệ) và vẫn truy cập được hệ thống hồ sơ bệnh án.

**Đề xuất sửa:** Xóa nhánh except fail-open trong get_current_user (app/medicare/common/auth.py). Khi kiểm tra phiên lỗi phải fail-closed: clear session và raise LoginRequired (hoặc trả 500), chỉ log. Không bao giờ dùng user_id thô từ session mà bỏ qua sv, is_active, iat.

#### 🔴 TP · MEDIUM · Thời hạn phiên do client tự chọn qua tham số shift, không có kiểm soát phía server — `app/medicare/common/auth.py:73`

CWE-613 · OWASP A07 · độ tin cậy 0.85 · nguồn: agent

**Phân tích:** Form field shift được người đăng nhập tự gửi; start_session lưu thẳng vào session và chỉ loại trừ PATIENT. Mọi nhân viên (hay kẻ có mật khẩu bị lộ) có thể chọn 24h; không kiểm tra ca thực tế. Giá trị không hợp lệ (shift=abc) được lưu mà không validate, khiến SHIFT_MAX_AGE[...] ném KeyError, kết hợp với nhánh fail-open ở get_current_user làm mất hoàn toàn kiểm tra hết hạn/thu hồi phiên: phiên tồn tại vĩnh viễn.

**Kịch bản khai thác:** Kẻ tấn công POST /login với shift=bogus: phiên được cấp, mọi request sau ném KeyError trong _max_age, đi vào nhánh except và không bao giờ hết hạn hay bị revoke.

**Đề xuất sửa:** Trong start_session (app/medicare/common/auth.py) validate shift theo whitelist SHIFT_MAX_AGE, giá trị lạ thì dùng DEFAULT_SHIFT hoặc từ chối. Chỉ cho phép phiên dài với vai trò lâm sàng cần thiết và tốt hơn xác định phía server (lịch trực); trong _max_age dùng .get với fallback an toàn. Cân nhắc giới hạn idle timeout cho phiên dài.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware nào trong app/medicare/main.py đặt X-Frame-Options hoặc CSP frame-ancestors; tìm kiếm trong repo không thấy header nào. Ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py, đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking; không có middleware đặt header trong main.py.

**Đề xuất sửa:** Dùng middleware security headers chung trong app/medicare/main.py với X-Frame-Options: DENY / frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app, không có middleware đặt header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health cũng thiếu X-Content-Type-Options do không có middleware chung đặt header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong toàn bộ code; middleware trong main.py không đặt header này.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 54.2 s · 25 lần gọi LLM · 15 lần gọi công cụ · 90494 token vào / 8508 token ra · ≈ $0.1623 · chạm giới hạn: không</sub>
