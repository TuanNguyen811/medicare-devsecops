<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c195b94`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Mass assignment trong update_profile: extra="allow" cho phép tự nâng quyền (role, department_id, patient_id, is_active) | `app/medicare/auth/schemas.py:8` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /account/profile:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · CRITICAL · Mass assignment trong update_profile: extra="allow" cho phép tự nâng quyền (role, department_id, patient_id, is_active) — `app/medicare/auth/schemas.py:8`

CWE-915 · OWASP A01 · vi phạm R-16 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** ProfileForm khai báo extra="allow" nên mọi trường thừa client gửi lên đều được giữ trong model. update_profile dùng form.model_dump(exclude={"csrf_token"}) rồi setattr(user, field, value) cho từng mục, nên các trường như role, department_id, patient_id, is_active cũng được ghi vào User. Điều này vi phạm R-16 (chỉ cho phép full_name, phone).

**Kịch bản khai thác:** Y tá đăng nhập rồi gửi POST /account/profile kèm role=ADMIN (hoặc patient_id=<id khác>, department_id) cùng CSRF token hợp lệ. Server setattr các trường này lên User và commit, nên kẻ tấn công thành ADMIN hoặc truy cập hồ sơ bệnh nhân bất kỳ.

**Đề xuất sửa:** Trong app/medicare/auth/schemas.py, đổi ProfileForm sang extra="forbid" hoặc "ignore" (csrf_token cần được khai báo hoặc bỏ qua rõ ràng). Trong update_profile ở router.py, không lặp qua model_dump nữa. Chỉ gán tường minh user.full_name = form.full_name và user.phone = form.phone, hoặc lặp trên allowlist cố định {"full_name","phone"}. Thêm test gửi role/department_id/patient_id/is_active và kiểm tra các trường này không đổi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options hay frame-ancestors, nên ứng dụng thật sự thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers dùng chung trong app factory: X-Frame-Options: DENY và CSP có frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Frame-Options hay frame-ancestors nào trong repo, nên trang /login có thể bị nhúng vào iframe.

**Đề xuất sửa:** Thêm middleware security headers dùng chung: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /account/profile:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu, nên các phản hồi đều thiếu CSP.

**Đề xuất sửa:** Thêm CSP trong middleware security headers dùng chung (default-src 'self', frame-ancestors 'none'), có tính đến script/style CDN của Bootstrap.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware security headers dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware security headers dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware security headers dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu, kể cả với /health. Rủi ro thấp.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers dùng chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers dùng chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 30.9 s · 14 lần gọi LLM · 13 lần gọi công cụ · 64236 token vào / 4549 token ra · ≈ $0.1095 · chạm giới hạn: không</sub>
