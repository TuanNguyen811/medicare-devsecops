<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c195b94`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Mass assignment: ProfileForm extra="allow" cho phép tự nâng quyền (role, department_id, password_hash) | `app/medicare/auth/schemas.py:8` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /account/profile:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · CRITICAL · Mass assignment: ProfileForm extra="allow" cho phép tự nâng quyền (role, department_id, password_hash) — `app/medicare/auth/schemas.py:8`

CWE-915 · OWASP A01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** ProfileForm cấu hình extra="allow" nên mọi field thừa trong form POST đều được giữ lại. update_profile lặp model_dump(exclude={"csrf_token"}) rồi setattr(user, field, value) cho mọi key, nên người dùng đăng nhập có thể ghi đè bất kỳ cột nào của User (role, department_id, password_hash, username, is_active...). Chỉ cần thêm role=admin vào POST.

**Kịch bản khai thác:** Lễ tân đăng nhập, gửi POST /account/profile với full_name hợp lệ cùng role=admin (hoặc doctor). Server setattr(user, "role", "admin") và commit, người dùng trở thành admin và truy cập toàn bộ dữ liệu bệnh nhân.

**Đề xuất sửa:** Trong app/medicare/auth/schemas.py đổi ProfileForm sang extra="forbid" (hoặc ignore). Trong update_profile (app/medicare/auth/router.py) không setattr theo vòng lặp động; chỉ gán tường minh user.full_name = form.full_name và user.phone = form.phone. Thêm test gửi role=admin và xác nhận role không đổi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy nơi nào đặt X-Frame-Options hay CSP frame-ancestors, nên ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware response header toàn cục (app factory) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Frame-Options/frame-ancestors nào trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /account/profile:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm header Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm header Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm header Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm header Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health do không có header toàn cục; mức thấp vì endpoint trả JSON.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 32.7 s · 14 lần gọi LLM · 13 lần gọi công cụ · 61103 token vào / 4750 token ra · ≈ $0.0960 · chạm giới hạn: không</sub>
