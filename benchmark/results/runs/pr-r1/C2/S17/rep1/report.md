<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 9 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `e503967`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | Mass assignment trong /account/profile cho phép tự nâng quyền (role, department_id, patient_id, is_active) | `app/medicare/auth/schemas.py:8` | agent | 0.95 |

### Chi tiết

#### 🔴 TP · CRITICAL · Mass assignment trong /account/profile cho phép tự nâng quyền (role, department_id, patient_id, is_active) — `app/medicare/auth/schemas.py:8`

CWE-915 · OWASP A01 · vi phạm R-16 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** ProfileForm dùng extra="allow", nên mọi trường form thừa (role, department_id, patient_id, is_active, password_hash...) được giữ lại trong model_dump(). update_profile lặp qua toàn bộ dict và setattr lên User, nên người dùng bất kỳ có thể ghi đè các trường quản trị. Điều này vi phạm R-16 (chỉ cho phép full_name, phone).

**Kịch bản khai thác:** Lễ tân đăng nhập rồi POST /account/profile với full_name=x&role=ADMIN (kèm csrf_token hợp lệ). setattr(user, "role", "ADMIN") được thực thi và db.commit() lưu lại, nên tài khoản trở thành ADMIN. Kẻ tấn công cũng có thể đặt patient_id để đọc hồ sơ của bệnh nhân khác.

**Đề xuất sửa:** Trong schemas.py, đặt extra="forbid" (hoặc "ignore") cho ProfileForm. Trong update_profile ở router.py, không lặp động qua model_dump. Chỉ gán tường minh user.full_name = form.full_name và user.phone = form.phone, hoặc dùng allowlist cố định {full_name, phone}. Nếu dùng forbid, hãy cho phép riêng csrf_token (khai báo trường này hoặc xử lý trước). Thêm test: gửi role/department_id/patient_id/is_active và xác nhận không đổi.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 9</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Tìm trong toàn repo không thấy ứng dụng đặt X-Frame-Options hay CSP frame-ancestors, nên các trang HTML có thể bị nhúng iframe (clickjacking). | Thêm middleware (hoặc cấu hình reverse proxy) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /account/profile`, `POST /appointments`, `POST /patients`, `POST /patients/{patient_id}/edit` | Repo không đặt Content-Security-Policy ở đâu, nên không có lớp phòng thủ chiều sâu chống XSS. | Thêm middleware toàn cục đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none'). |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Repo không đặt X-Content-Type-Options ở đâu. | Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Repo không đặt X-Content-Type-Options ở đâu. | Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 34.9 s · 14 lần gọi LLM · 13 lần gọi công cụ · 81806 token vào / 4950 token ra · ≈ $0.1167 · chạm giới hạn: không</sub>
