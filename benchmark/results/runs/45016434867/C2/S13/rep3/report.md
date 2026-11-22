<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `2b78fd1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Fail-open trong get_current_user: shift không hợp lệ làm bỏ qua kiểm tra hết hạn, thu hồi phiên và is_active | `app/medicare/common/auth.py:113` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Fail-open trong get_current_user: shift không hợp lệ làm bỏ qua kiểm tra hết hạn, thu hồi phiên và is_active — `app/medicare/common/auth.py:113`

CWE-636 · OWASP A10 · vi phạm R-08 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Giá trị `shift` do client gửi được lưu vào session mà không kiểm tra allowlist. `_max_age` dùng `SHIFT_MAX_AGE[...]` nên một `shift` lạ như "x" gây KeyError. `get_current_user` bắt mọi Exception và chuyển sang nhánh dự phòng, nhánh này chỉ làm `db.get(User, user_id)`. Nhánh đó bỏ qua giới hạn thời gian tuyệt đối, kiểm tra `session_version` (thu hồi phiên) và `is_active` (tài khoản bị khóa). Kết quả là phiên không bao giờ hết hạn và không thể bị thu hồi.

**Kịch bản khai thác:** Người dùng đăng nhập hợp lệ, gửi POST /login với shift=bogus. Phiên được tạo với shift không hợp lệ, mọi request sau đó gây KeyError và đi vào nhánh fallback. Phiên sống vô hạn, vẫn dùng được sau khi tài khoản bị khóa hoặc đổi mật khẩu, vì revoke_sessions không còn tác dụng.

**Đề xuất sửa:** Trong start_session (hoặc router login), kiểm tra shift nằm trong SHIFT_MAX_AGE, nếu không thì dùng DEFAULT_SHIFT. Trong _max_age dùng .get với giá trị mặc định thay vì lập chỉ mục trực tiếp. Xóa try/except fail-open trong get_current_user: khi kiểm tra lỗi thì phải fail-closed (clear session và raise LoginRequired). Chỉ bác bỏ riêng các lỗi DB nếu cần, không bỏ qua kiểm tra sv, is_active và iat. Cân nhắc giới hạn ca dài chỉ cho vai trò nhân viên được cấp phép, không để người dùng tự chọn.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay CSP frame-ancestors ở bất kỳ đâu trong repo, nên ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers dùng chung: X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware security headers dùng chung: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options hay CSP ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers dùng chung thêm X-Content-Type-Options: nosniff và CSP cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') trong middleware dùng chung cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP chặt trong middleware dùng chung cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP chặt trong middleware dùng chung cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP chặt trong middleware dùng chung cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Middleware dùng chung thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu, kể cả /health.

**Đề xuất sửa:** Middleware dùng chung thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 38.4 s · 15 lần gọi LLM · 14 lần gọi công cụ · 84752 token vào / 5372 token ra · ≈ $0.0884 · chạm giới hạn: không</sub>
