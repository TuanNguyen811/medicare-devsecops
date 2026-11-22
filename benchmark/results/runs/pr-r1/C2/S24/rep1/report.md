<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 9 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `6527fb1`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | Remember-me token vô hiệu hóa khóa tài khoản, cho phép brute-force mật khẩu không giới hạn | `app/medicare/common/auth.py:54` | agent | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · Remember-me token vô hiệu hóa khóa tài khoản, cho phép brute-force mật khẩu không giới hạn — `app/medicare/common/auth.py:54`

CWE-307 · OWASP A07 · vi phạm R-07 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** authenticate() bỏ qua kiểm tra locked_until và không tăng failed_login_count khi remembered_device=True. Cờ này chỉ dựa vào việc cookie medicare_remember của request khớp BẤT KỲ token hợp lệ nào (is_remembered_device không gắn với username đang đăng nhập). Kẻ tấn công chỉ cần có tài khoản hợp lệ của chính mình, bật "ghi nhớ", rồi gửi cookie đó kèm mọi lần đoán mật khẩu của tài khoản nạn nhân: không bị khóa, không bị đếm. Lỗi này phá vỡ R-07 (khóa 15 phút sau 5 lần sai). Ngoài ra khi tài khoản đang bị khóa, kẻ tấn công vẫn đăng nhập được nếu đoán đúng.

**Kịch bản khai thác:** Kẻ tấn công đăng nhập tài khoản của mình với remember_me, lấy cookie medicare_remember, rồi tự động gửi hàng triệu mật khẩu cho username của bác sĩ kèm cookie này; server không khóa và không đếm lần sai.

**Đề xuất sửa:** Xóa tham số remembered_device khỏi authenticate() trong app/medicare/common/auth.py và bỏ remember.is_remembered_device trong login (auth/router.py): luôn áp dụng khóa và đếm lần sai theo R-07 cho mọi lần đăng nhập bằng mật khẩu, bất kể cookie remember.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 9</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Ứng dụng không có middleware nào thêm X-Frame-Options hoặc CSP frame-ancestors; create_app chỉ có CatchAllErrors, Session và Metrics. Trang đăng nhập và các trang có thể bị nhúng vào iframe (clickjacking). | Thêm một middleware bảo mật trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') trên mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có Content-Security-Policy ở bất kỳ response nào vì không có middleware đặt header. | Thêm middleware đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong create_app, main.py. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options trên toàn ứng dụng. | Thêm X-Content-Type-Options: nosniff qua middleware security headers trong main.py. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Không có middleware nào đặt X-Content-Type-Options: nosniff. | Thêm middleware security headers trong main.py đặt X-Content-Type-Options: nosniff. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 37.5 s · 15 lần gọi LLM · 14 lần gọi công cụ · 97759 token vào / 5767 token ra · ≈ $0.1430 · chạm giới hạn: không</sub>
