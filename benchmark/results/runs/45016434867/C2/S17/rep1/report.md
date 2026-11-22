<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c195b94`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | Mass assignment trong /account/profile: ProfileForm extra="allow" cho phép ghi role, department_id, patient_id, is_active | `app/medicare/auth/schemas.py:9` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /account/profile:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · Mass assignment trong /account/profile: ProfileForm extra="allow" cho phép ghi role, department_id, patient_id, is_active — `app/medicare/auth/schemas.py:9`

CWE-915 · OWASP A01 · vi phạm R-16 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** ProfileForm khai báo extra="allow" nên mọi trường form thừa đều được giữ lại trong model. update_profile lặp qua form.model_dump(exclude={"csrf_token"}) và setattr lên User cho từng khóa, nên các trường như role, department_id, patient_id, is_active, password_hash cũng bị ghi. Điều này vi phạm R-16: server phải bỏ qua hoặc từ chối mọi trường ngoài allowlist (full_name, phone).

**Kịch bản khai thác:** Một lễ tân đã đăng nhập gửi POST /account/profile với CSRF token hợp lệ cùng các trường thừa role=ADMIN. Server setattr(user, "role", "ADMIN") rồi commit, nên người đó trở thành ADMIN. Tương tự, họ có thể đổi patient_id để đọc hồ sơ của bệnh nhân khác.

**Đề xuất sửa:** Trong app/medicare/auth/schemas.py, đổi ProfileForm thành extra="forbid" (hoặc "ignore"). Trong update_profile ở router.py, không dùng vòng lặp setattr trên model_dump. Chỉ gán tường minh user.full_name = form.full_name và user.phone = form.phone (allowlist theo R-16). Thêm test gửi kèm role/department_id/patient_id/is_active và xác nhận các trường này không đổi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay frame-ancestors, nên ứng dụng không chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers trong app factory: X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống framing trong repo, kể cả với trang /login.

**Đề xuất sửa:** Dùng chung middleware security headers: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers, thêm X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /account/profile:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu cả.

**Đề xuất sửa:** Thêm CSP (default-src 'self', frame-ancestors 'none') qua middleware toàn cục, điều chỉnh cho tài nguyên Bootstrap đang dùng.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu cả.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu cả.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu cả.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo. Endpoint /health có rủi ro thấp, nhưng header nên áp dụng toàn cục.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 36.7 s · 14 lần gọi LLM · 13 lần gọi công cụ · 65811 token vào / 4702 token ra · ≈ $0.1118 · chạm giới hạn: không</sub>
