<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `2b78fd1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | get_current_user fail-open: lỗi khi kiểm tra session thì bỏ qua mọi kiểm tra; shift không được validate | `app/medicare/common/auth.py:115` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · get_current_user fail-open: lỗi khi kiểm tra session thì bỏ qua mọi kiểm tra; shift không được validate — `app/medicare/common/auth.py:115`

CWE-636 · OWASP A10 · vi phạm R-08 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Khi _session_user ném exception, nhánh except lấy user trực tiếp bằng db.get theo user_id mà không kiểm tra is_active, session_version (sv) hay thời hạn tuyệt đối (iat). Giá trị shift từ form được lưu vào session mà không validate; shift lạ khiến SHIFT_MAX_AGE[...] ném KeyError ở mọi request, nên session đó luôn đi vào nhánh fail-open: không bao giờ hết hạn và không bị revoke_sessions / khóa tài khoản vô hiệu hóa.

**Kịch bản khai thác:** Người dùng POST /login với shift=bogus. Session chứa shift không hợp lệ nên _max_age ném KeyError ở mọi request; nhánh except bỏ qua kiểm tra sv, is_active và iat. Session sống vĩnh viễn và không bị vô hiệu khi đổi mật khẩu, khóa tài khoản hay revoke_sessions.

**Đề xuất sửa:** Trong get_current_user (app/medicare/common/auth.py) bỏ nhánh fallback: khi có exception thì xóa session và raise LoginRequired (fail-closed), chỉ log lỗi. Trong router login / start_session, validate shift theo allowlist SHIFT_MAX_AGE (giá trị lạ thì dùng DEFAULT_SHIFT hoặc trả 422); trong _max_age dùng .get với mặc định thay vì index trực tiếp.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay CSP frame-ancestors; main.py chỉ có middleware lỗi, session, metrics.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py: X-Frame-Options DENY và CSP có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có header chống nhúng frame; không có middleware đặt header trong repo.

**Đề xuất sửa:** Dùng middleware security headers chung trong app/medicare/main.py (X-Frame-Options DENY, CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options: nosniff ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở response nào.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self') trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP ở response nào.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP ở response nào.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP ở response nào.

**Đề xuất sửa:** Thêm CSP trong middleware security headers chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu nosniff trên mọi response, gồm GET /.

**Đề xuất sửa:** Thêm nosniff trong middleware security headers chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff cho /health vì không có middleware đặt header. Rủi ro thấp.

**Đề xuất sửa:** Thêm nosniff trong middleware security headers chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 61.6 s · 26 lần gọi LLM · 15 lần gọi công cụ · 141324 token vào / 8982 token ra · ≈ $0.1948 · chạm giới hạn: không</sub>
