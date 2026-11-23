<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `689d6dd`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | Fail-open trong get_current_user: shift không hợp lệ vô hiệu hóa kiểm tra session | `app/medicare/common/auth.py:88` | agent | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · Fail-open trong get_current_user: shift không hợp lệ vô hiệu hóa kiểm tra session — `app/medicare/common/auth.py:88`

CWE-636 · OWASP A10 · vi phạm R-08 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** `login` nhận `shift` từ form không validate và `start_session` lưu thẳng vào session. `_max_age` dùng `SHIFT_MAX_AGE[...]` nên giá trị lạ (ví dụ "x") gây KeyError. Lỗi này nằm trong `_session_user`, bị `except Exception` trong `get_current_user` bắt, và nhánh fallback lấy user từ session mà không kiểm tra hạn tuyệt đối (iat), `session_version` hay `is_active`. Kết quả: session không bao giờ hết hạn, không bị thu hồi (revoke_sessions, đổi mật khẩu, khóa tài khoản đều vô hiệu), và người dùng bị khóa vẫn truy cập được.

**Kịch bản khai thác:** Kẻ tấn công (hoặc nhân viên bị thu hồi quyền) đăng nhập với shift=bogus. Mọi request sau đó gây KeyError và đi vào nhánh fallback, nên session sống vĩnh viễn và vẫn hợp lệ sau khi admin khóa tài khoản hoặc tăng session_version. Cookie bị đánh cắp cũng dùng được mãi.

**Đề xuất sửa:** Trong auth/router.py `login` và `start_session`, chỉ chấp nhận shift nằm trong SHIFT_MAX_AGE, giá trị lạ thì dùng DEFAULT_SHIFT hoặc trả lỗi 400. Trong `_max_age` dùng `.get` với mặc định an toàn. Quan trọng nhất: bỏ nhánh fallback fail-open trong `get_current_user`. Khi kiểm tra session lỗi thì xóa session và raise LoginRequired (fail-closed), chỉ log loại lỗi. Cân nhắc giới hạn shift dài cho các vai trò nhân viên được phép.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Không có middleware hay cấu hình nào đặt X-Frame-Options hoặc CSP frame-ancestors (main.py chỉ có Session, Metrics, CatchAll middleware). Ứng dụng có thể bị nhúng iframe (clickjacking). | Thêm một middleware security headers trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `GET /login`, `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có mã nào đặt X-Content-Type-Options: nosniff hay CSP (tìm kiếm toàn repo không thấy). | Thêm middleware đặt X-Content-Type-Options: nosniff và CSP cho mọi response trong app/medicare/main.py. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Không có mã nào đặt X-Content-Type-Options: nosniff. | Đặt X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 38.6 s · 16 lần gọi LLM · 15 lần gọi công cụ · 84985 token vào / 5623 token ra · ≈ $0.1309 · chạm giới hạn: không</sub>
