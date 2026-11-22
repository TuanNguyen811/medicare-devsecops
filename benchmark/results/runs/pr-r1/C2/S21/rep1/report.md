<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 2 lỗi cần sửa (2 do Agent tự tìm, công cụ quét không báo)

🟢 2 báo nhầm của công cụ quét đã được gỡ · 📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `36f2115`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | Token đặt lại mật khẩu không hết hạn sau 15 phút và không dùng một lần | `app/medicare/auth/reset.py:47` | agent | 0.90 |
| 🔴 TP | MEDIUM | Liệt kê tài khoản qua phản hồi /forgot-password khác nhau | `app/medicare/auth/router.py:122` | agent | 0.95 |

### Chi tiết

#### 🔴 TP · HIGH · Token đặt lại mật khẩu không hết hạn sau 15 phút và không dùng một lần — `app/medicare/auth/reset.py:47`

CWE-640 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** RESET_TOKEN_TTL được khai báo nhưng user_for_token không so sánh created_at với TTL; reset_password không xóa/đánh dấu token đã dùng. Token vì vậy có hiệu lực vô thời hạn và dùng được nhiều lần, vi phạm R-18.

**Kịch bản khai thác:** Kẻ có được liên kết cũ (lịch sử trình duyệt, hộp thư bị lộ, log proxy) vài tuần sau, hoặc sau khi nạn nhân đã đặt lại, vẫn dùng lại để đặt mật khẩu mới và chiếm tài khoản.

**Đề xuất sửa:** Trong reset.user_for_token, từ chối token có created_at cũ hơn RESET_TOKEN_TTL (so sánh với thời gian hiện tại). Trong reset.reset_password (hoặc router.reset_password) xóa token đã dùng và xóa mọi token khác của user đó trong cùng giao dịch trước khi commit. Cân nhắc dọn token hết hạn khi tạo token mới.

#### 🔴 TP · MEDIUM · Liệt kê tài khoản qua phản hồi /forgot-password khác nhau — `app/medicare/auth/router.py:122`

CWE-204 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Khi email không tồn tại, server trả lỗi "Không tìm thấy tài khoản nào đăng ký với email này"; khi tồn tại thì chuyển hướng 303 kèm flash. R-18 và R-07 yêu cầu phản hồi giống hệt. Không có rate limit nên có thể dò email hàng loạt của nhân viên/bệnh nhân.

**Kịch bản khai thác:** Kẻ tấn công gửi danh sách email và phân biệt email hợp lệ qua thông báo lỗi để phục vụ phishing hoặc tấn công tiếp theo.

**Đề xuất sửa:** Trong router.forgot_password luôn trả cùng một phản hồi (flash chung + redirect 303 /login) bất kể request_reset trả True hay False; không phản chiếu lỗi 'không tìm thấy'. Thời gian xử lý cũng nên tương đương (ví dụ gửi mail bất đồng bộ) và nên thêm giới hạn tần suất theo IP/email.

<details><summary>🟢 Báo nhầm của công cụ quét đã gỡ: 2</summary>

- **B107 (bandit)** — `app/medicare/auth/router.py:134`: '' chỉ là giá trị mặc định rỗng của tham số query token, không phải mật khẩu cứng; token rỗng bị user_for_token từ chối.
- **generic-api-key (gitleaks)** — `app/tests/test_password_reset.py:15`: Dòng bị báo nằm trong file test (app/tests/test_password_reset.py), là hằng số mật khẩu mới giả (NEW_PASSWORD) dùng trong test, không phải secret thật. Nội dung dòng bị che nên đánh giá dựa trên cách dùng trong test.

</details>

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /forgot-password`, `GET /login` | Không có middleware nào đặt X-Frame-Options/CSP frame-ancestors (tìm toàn repo không thấy), nên trang có thể bị nhúng iframe (clickjacking). | Thêm middleware trong app/medicare/main.py đặt header bảo mật cho mọi response: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff, Content-Security-Policy. |
| xác nhận | MEDIUM | 10038 (zap) | `GET /reset-password`, `POST /forgot-password`, `POST /reset-password` | Không có Content-Security-Policy nào được đặt trong ứng dụng. Trang /reset-password còn chứa token trong URL nên cần thêm Referrer-Policy: no-referrer. | Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') và Referrer-Policy: no-referrer trong middleware header chung ở app/medicare/main.py. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Không có X-Content-Type-Options trên toàn ứng dụng. | Thêm X-Content-Type-Options: nosniff vào middleware header bảo mật chung trong app/medicare/main.py. |
| xác nhận | LOW | 10038 (zap) | `GET /forgot-password`, `GET /login` | Không có middleware đặt X-Content-Type-Options: nosniff (tìm toàn repo không thấy). | Thêm X-Content-Type-Options: nosniff vào middleware header bảo mật chung trong app/medicare/main.py. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 47.7 s · 20 lần gọi LLM · 19 lần gọi công cụ · 127723 token vào / 7362 token ra · ≈ $0.1904 · chạm giới hạn: không</sub>
