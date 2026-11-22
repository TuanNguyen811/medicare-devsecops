<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 2 lỗi thật (TP) · 10 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `f923a00`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Cookie remember-me bất kỳ vô hiệu hóa khóa tài khoản và đếm lần sai (brute-force mật khẩu) | `app/medicare/common/auth.py:54` | 0.90 |
| 🔴 TP | MEDIUM | agent | Logout không thu hồi remember token phía server | `app/medicare/auth/router.py:60` | 0.80 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.40 |

### Chi tiết

#### 🔴 TP · HIGH · Cookie remember-me bất kỳ vô hiệu hóa khóa tài khoản và đếm lần sai (brute-force mật khẩu) — `app/medicare/common/auth.py:54`

CWE-307 · OWASP A07 · vi phạm R-07 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** login() truyền remembered_device=remember.is_remembered_device(...) vào authenticate(). Hàm này chỉ kiểm tra cookie có token hợp lệ của BẤT KỲ người dùng nào, không gắn với username đang đăng nhập. Khi remembered_device=True, authenticate bỏ qua kiểm tra locked_until và không tăng failed_login_count. Kẻ tấn công chỉ cần đăng nhập bằng tài khoản của chính mình với remember_me=on để lấy cookie hợp lệ, sau đó dùng cookie đó để thử mật khẩu không giới hạn lên mọi tài khoản (kể cả tài khoản đang bị khóa), phá vỡ R-07 (khóa 15 phút sau 5 lần sai).

**Kịch bản khai thác:** Kẻ tấn công có tài khoản hợp lệ, đăng nhập với remember_me=on để nhận cookie medicare_remember. Sau đó gửi hàng nghìn request POST /login kèm cookie này với username của bác sĩ và danh sách mật khẩu; không bị khóa và bộ đếm không tăng nên có thể dò được mật khẩu.

**Đề xuất sửa:** Xóa tham số remembered_device khỏi authenticate() trong app/medicare/common/auth.py và bỏ remember.is_remembered_device() trong login() (router.py): luôn áp dụng khóa tài khoản và đếm lần sai cho mọi lần đăng nhập bằng mật khẩu (R-07). Nếu cần ngoại lệ, phải gắn token với đúng user_id của username đang đăng nhập và vẫn không được bỏ qua lockout.

#### 🔴 TP · MEDIUM · Logout không thu hồi remember token phía server — `app/medicare/auth/router.py:60`

CWE-613 · OWASP A07 · vi phạm R-08 · độ tin cậy 0.80 · nguồn: agent

**Phân tích:** logout() chỉ tăng session_version và xóa cookie trên trình duyệt hiện tại; bản ghi RememberToken vẫn còn trong DB đến 30 ngày. Cookie bị sao chép/đánh cắp vẫn được get_current_user chấp nhận qua remembered_user() và tạo lại session sau khi người dùng đã đăng xuất. Token cũng không được xoay vòng khi sử dụng.

**Kịch bản khai thác:** Người dùng đăng xuất trên máy dùng chung; kẻ khác đã chép cookie medicare_remember vẫn vào lại được tài khoản trong 30 ngày.

**Đề xuất sửa:** Trong logout() (router.py) đọc cookie remember, tìm RememberToken theo hash và xóa bản ghi đó (hoặc gọi remember.revoke_all(db, user)) trước db.commit(). Cân nhắc xoay vòng token mỗi lần dùng trong remembered_user().

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không có mã middleware đặt security header trong ngữ cảnh được cung cấp, không thể xác nhận hay bác bỏ. Cần kiểm tra middleware header.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy middleware đặt X-Frame-Options/frame-ancestors trong ngữ cảnh; không đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy mã đặt X-Content-Type-Options trong ngữ cảnh; không đủ bằng chứng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy cấu hình CSP trong ngữ cảnh; PR không đụng vào header nên cần xem middleware toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy cấu hình CSP trong ngữ cảnh; cần xem middleware toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy cấu hình CSP trong ngữ cảnh; cần xem middleware toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy cấu hình CSP trong ngữ cảnh; cần xem middleware toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy cấu hình CSP trong ngữ cảnh; cần xem middleware toàn cục.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy mã đặt X-Content-Type-Options trong ngữ cảnh; không đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Không thấy mã đặt X-Content-Type-Options trong ngữ cảnh; không đủ bằng chứng.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 35.1 s · 14 lần gọi LLM · 13 lần gọi công cụ · 61047 token vào / 5437 token ra · ≈ $0.1811 · chạm giới hạn: không</sub>
