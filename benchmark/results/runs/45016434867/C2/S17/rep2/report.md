<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c195b94`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Mass assignment ở /account/profile: ProfileForm extra="allow" cho phép ghi đè role, department_id, patient_id, is_active | `app/medicare/auth/schemas.py:8` | 0.95 |
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

#### 🔴 TP · CRITICAL · Mass assignment ở /account/profile: ProfileForm extra="allow" cho phép ghi đè role, department_id, patient_id, is_active — `app/medicare/auth/schemas.py:8`

CWE-915 · OWASP A01 · vi phạm R-16 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** ProfileForm khai báo extra="allow", nên mọi trường form thừa đều được giữ lại trong model_dump(). update_profile lặp qua toàn bộ rồi setattr(user, field, value) lên đối tượng User, chỉ loại trừ csrf_token. Người dùng đã đăng nhập chỉ cần gửi thêm role=ADMIN, department_id, patient_id, password_hash hoặc is_active để leo thang đặc quyền hoặc chiếm hồ sơ bệnh nhân. Vi phạm R-16 (chỉ cho phép họ tên và số điện thoại).

**Kịch bản khai thác:** Lễ tân đăng nhập rồi POST /account/profile với full_name=x&role=ADMIN&csrf_token=... Server setattr(user,"role","ADMIN") và commit, tài khoản trở thành ADMIN. Tương tự, đặt patient_id để đọc hồ sơ bệnh nhân bất kỳ.

**Đề xuất sửa:** Trong schemas.py, đổi ProfileForm sang extra="forbid" (hoặc "ignore"). Trong router.py update_profile, không lặp setattr trên mọi khóa; chỉ gán tường minh user.full_name = form.full_name và user.phone = form.phone (hoặc đối chiếu với allowlist {full_name, phone}). Thêm test gửi role/department_id/patient_id/is_active và xác nhận không đổi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không có header X-Frame-Options hay CSP frame-ancestors nào (search_code không thấy), main.py chỉ có middleware lỗi và metrics. Trang có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trên toàn ứng dụng, kể cả /login.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /account/profile:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') qua middleware trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; middleware toàn cục sẽ áp dụng cho cả endpoint này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 36.1 s · 15 lần gọi LLM · 14 lần gọi công cụ · 81083 token vào / 5118 token ra · ≈ $0.0818 · chạm giới hạn: không</sub>
