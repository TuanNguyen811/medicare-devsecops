<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 1 lỗi thật (TP) · 9 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `2b78fd1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Fail-open trong get_current_user kết hợp `shift` không được kiểm tra: phiên không bao giờ hết hạn và không bị thu hồi | `app/medicare/common/auth.py:88` | 0.90 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.40 |

### Chi tiết

#### 🔴 TP · HIGH · Fail-open trong get_current_user kết hợp `shift` không được kiểm tra: phiên không bao giờ hết hạn và không bị thu hồi — `app/medicare/common/auth.py:88`

CWE-636 · OWASP A10 · vi phạm R-08 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Tham số `shift` từ form được lưu thẳng vào session trong start_session mà không đối chiếu với SHIFT_MAX_AGE (chỉ ép về mặc định cho PATIENT). Khi shift là giá trị lạ (ví dụ "x"), `_max_age` thực hiện `SHIFT_MAX_AGE[...]` và ném KeyError. `get_current_user` bắt mọi Exception rồi fail-open: lấy user theo `user_id` trong session mà bỏ qua kiểm tra hạn phiên (`iat`), `is_active` và `session_version`. Hậu quả: phiên không bao giờ hết hạn, vẫn sống sau logout, đổi mật khẩu (revoke_sessions) hoặc khi tài khoản bị khóa/vô hiệu hóa. Điều này phá vỡ R-08 và R-18 (thu hồi phiên). Bệnh nhân cũng bị ảnh hưởng vì chỉ lúc login shift mới được ép về mặc định, nhưng với PATIENT giá trị đã bị ghi đè nên không bị; mọi vai trò nhân viên (kể cả ADMIN) thì có. Ngoài ra bất kỳ nhân viên nào cũng tự chọn được phiên 24h.

**Kịch bản khai thác:** Nhân viên (hoặc kẻ có thông tin đăng nhập bị lộ) gửi POST /login với `shift=bogus`. Session được tạo với shift không hợp lệ; mọi request sau đó gây KeyError trong _max_age, bị nuốt và đi qua nhánh fallback. Phiên không hết hạn và không bị vô hiệu bởi logout, đổi mật khẩu hay khóa tài khoản; cookie bị đánh cắp dùng được vô thời hạn.

**Đề xuất sửa:** 1) Trong router.py `login` / auth.py `start_session`: kiểm tra `shift` nằm trong `SHIFT_MAX_AGE` (allowlist); nếu không thì dùng DEFAULT_SHIFT hoặc trả lỗi 422. 2) Trong `_max_age` dùng `SHIFT_MAX_AGE.get(shift)` và rơi về session_max_age khi giá trị lạ. 3) Trong `get_current_user` bỏ nhánh fallback fail-open: khi `_session_user` ném ngoại lệ thì log và fail-closed (clear session, raise LoginRequired, hoặc trả 500), tuyệt đối không bỏ qua kiểm tra iat, is_active, session_version. 4) Cân nhắc giới hạn việc chọn ca 12h/24h theo vai trò thay vì để người dùng tự chọn.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Đây là cảnh báo header phản hồi từ DAST. Các file PR không chứa middleware đặt header bảo mật nên không đủ bằng chứng để xác nhận hay bác bỏ; cần xem cấu hình middleware/reverse proxy.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu header chống clickjacking trên /login (trang đăng nhập). Không thấy cấu hình header trong PR nên không thể xác nhận; cần kiểm tra middleware.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /login; không có bằng chứng mã trong phần đã thấy, cần xem middleware.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /appointments; route này không nằm trong các file đã đọc, cần kiểm tra cấu hình header toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP trên route confirm lịch hẹn; không đủ bằng chứng trong PR, cần kiểm tra header toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients; cần kiểm tra middleware header toàn cục, không có trong phần đã đọc.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients/{patient_id}/edit; cần kiểm tra middleware header toàn cục, không có trong phần đã đọc.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: không có mã middleware header trong phần đã thấy của PR, cần kiểm tra cấu hình để quyết định.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health: không có bằng chứng mã trong phần đã thấy; cần xem middleware.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 35.1 s · 12 lần gọi LLM · 11 lần gọi công cụ · 44989 token vào / 5058 token ra · ≈ $0.1430 · chạm giới hạn: không</sub>
