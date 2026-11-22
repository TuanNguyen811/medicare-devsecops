<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c195b94`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Mass assignment ở POST /account/profile cho phép tự nâng quyền (role, department_id, patient_id, is_active) | `app/medicare/auth/schemas.py:9` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /account/profile:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.55 |

### Chi tiết

#### 🔴 TP · CRITICAL · Mass assignment ở POST /account/profile cho phép tự nâng quyền (role, department_id, patient_id, is_active) — `app/medicare/auth/schemas.py:9`

CWE-915 · OWASP A01 · vi phạm R-16 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** ProfileForm khai báo extra="allow" nên mọi trường client gửi thêm đều được giữ lại trong model_dump(). Handler update_profile chỉ loại csrf_token rồi setattr từng cặp lên đối tượng User, nên người dùng có thể gửi role=ADMIN, department_id, patient_id, is_active, password_hash, session_version, failed_login_count, locked_until... và ghi thẳng vào DB. Vi phạm R-16 (chỉ cho phép full_name và phone).

**Kịch bản khai thác:** Lễ tân đăng nhập, gửi POST /account/profile với full_name hợp lệ kèm role=ADMIN (có CSRF token hợp lệ). Server setattr(user, "role", "ADMIN") và commit; tài khoản trở thành ADMIN. Tương tự có thể gắn patient_id của bệnh nhân khác để đọc hồ sơ của họ.

**Đề xuất sửa:** Trong app/medicare/auth/schemas.py đổi ProfileForm thành extra="forbid" (hoặc "ignore"), và trong update_profile (app/medicare/auth/router.py) không lặp setattr trên toàn bộ model_dump; chỉ gán tường minh user.full_name = form.full_name và user.phone = form.phone (hoặc lặp trên allowlist cố định {"full_name","phone"}). Với forbid cần xử lý csrf_token (khai báo trường hoặc loại bỏ trước khi validate). Thêm test gửi role/department_id/is_active và xác nhận không thay đổi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** ZAP quan sát thực tế phản hồi HTML thiếu X-Frame-Options / frame-ancestors; không thấy cấu hình header bảo mật nào trong code. Ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware toàn cục trong app factory đặt X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking, có thể bị nhúng iframe để lừa nhập thông tin đăng nhập.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang GET / thiếu X-Content-Type-Options: nosniff.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** /health thiếu X-Content-Type-Options; rủi ro rất thấp nhưng sửa chung cùng middleware toàn cục.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên /login; là cấu hình thiếu header toàn cục, rủi ro thấp.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /account/profile:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Phản hồi của POST /account/profile không có CSP. Cùng nguyên nhân thiếu middleware header toàn cục; tác động thấp vì thường là redirect 303.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware toàn cục (default-src 'self', cho phép cdn.jsdelivr.net cần thiết, frame-ancestors 'none').

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /appointments; cùng nguyên nhân thiếu header toàn cục.

**Đề xuất sửa:** Đặt CSP bằng middleware toàn cục để áp dụng cho mọi route.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients; cùng nguyên nhân thiếu header toàn cục.

**Đề xuất sửa:** Đặt CSP bằng middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients/{patient_id}/edit; cùng nguyên nhân thiếu header toàn cục.

**Đề xuất sửa:** Đặt CSP bằng middleware toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 31.2 s · 12 lần gọi LLM · 11 lần gọi công cụ · 47933 token vào / 4709 token ra · ≈ $0.1452 · chạm giới hạn: không</sub>
