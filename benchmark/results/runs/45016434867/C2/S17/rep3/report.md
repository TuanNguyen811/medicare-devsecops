<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c195b94`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Mass assignment trong /account/profile: ProfileForm extra="allow" cho phép ghi role, department_id, patient_id, is_active | `app/medicare/auth/schemas.py:9` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /account/profile:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · CRITICAL · Mass assignment trong /account/profile: ProfileForm extra="allow" cho phép ghi role, department_id, patient_id, is_active — `app/medicare/auth/schemas.py:9`

CWE-915 · OWASP A01 · vi phạm R-16 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** ProfileForm khai báo extra="allow" nên mọi trường form thừa (vd role, department_id, patient_id, is_active, password_hash) được giữ lại trong model. update_profile gọi form.model_dump(exclude={"csrf_token"}) rồi setattr từng cặp lên user, nên các trường thừa đó được ghi thẳng vào bản ghi User. Người dùng bất kỳ có thể tự nâng quyền lên ADMIN hoặc gắn tài khoản vào hồ sơ bệnh nhân khác. Vi phạm R-16: server phải bỏ qua hoặc từ chối mọi trường ngoài họ tên và số điện thoại.

**Kịch bản khai thác:** Một bệnh nhân đã đăng nhập gửi POST /account/profile kèm CSRF token hợp lệ và thêm trường role=ADMIN (hoặc patient_id=<id bệnh nhân khác>). Server setattr các trường này lên User và commit. Kẻ tấn công thành ADMIN hoặc đọc được hồ sơ của bệnh nhân khác.

**Đề xuất sửa:** Trong app/medicare/auth/schemas.py đổi ProfileForm sang extra="forbid" (hoặc "ignore"). Trong update_profile ở app/medicare/auth/router.py không lặp setattr trên model_dump chung nữa. Chỉ gán tường minh user.full_name = form.full_name và user.phone = form.phone, hoặc lặp trên allowlist cố định {full_name, phone}. Thêm test gửi role/department_id/patient_id/is_active và xác nhận các giá trị đó không đổi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options hay CSP frame-ancestors, nên ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers dùng chung cho toàn app: X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo, kể cả trang /login.

**Đề xuất sửa:** Dùng cùng middleware security headers: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /account/profile:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu nosniff, không có middleware đặt header này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff trên /health. Rủi ro thấp nhưng cùng nguyên nhân với F2.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options: nosniff ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 31.9 s · 14 lần gọi LLM · 13 lần gọi công cụ · 65719 token vào / 4771 token ra · ≈ $0.0753 · chạm giới hạn: không</sub>
