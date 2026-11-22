<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `4c8160d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Token đặt lại mật khẩu không bao giờ hết hạn và không dùng một lần | `app/medicare/auth/reset.py:47` | 0.90 |
| 🔴 TP | MEDIUM | agent | Liệt kê tài khoản (user enumeration) và không giới hạn tần suất ở /forgot-password | `app/medicare/auth/router.py:123` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /forgot-password:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /reset-password:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /forgot-password:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /reset-password:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /forgot-password:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.75 |
| 🟡 NEEDS_REVIEW | LOW | gitleaks | generic-api-key (gitleaks) | `app/tests/test_password_reset.py:15` | 0.50 |
| 🟢 FP | LOW | bandit | B107 (bandit) | `app/medicare/auth/router.py:134` | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · Token đặt lại mật khẩu không bao giờ hết hạn và không dùng một lần — `app/medicare/auth/reset.py:47`

CWE-640 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** RESET_TOKEN_TTL được khai báo và dùng trong nội dung email ("15 phút") nhưng user_for_token không kiểm tra created_at. Token cũng không bị xóa/đánh dấu đã dùng sau reset_password, và token cũ của cùng user không bị vô hiệu khi phát token mới. Link rò rỉ (lịch sử mail, log, Referer) có hiệu lực vĩnh viễn và dùng lại được để chiếm tài khoản.

**Kịch bản khai thác:** Kẻ tấn công có được link reset cũ (vài tháng trước) và đặt lại mật khẩu, kể cả sau khi người dùng đã dùng link đó.

**Đề xuất sửa:** Trong reset.user_for_token, so sánh reset.created_at với now() - RESET_TOKEN_TTL và trả None nếu quá hạn. Trong reset_password (reset.py) xóa toàn bộ PasswordResetToken của user sau khi đổi mật khẩu (single-use); trong request_reset xóa token cũ của user trước khi phát token mới. Có thể dọn token hết hạn định kỳ.

#### 🔴 TP · MEDIUM · Liệt kê tài khoản (user enumeration) và không giới hạn tần suất ở /forgot-password — `app/medicare/auth/router.py:123`

CWE-204 · OWASP A07 · độ tin cậy 0.85 · nguồn: agent

**Phân tích:** Endpoint công khai trả thông báo khác nhau khi email tồn tại hay không, cho phép dò email nhân viên/bệnh nhân. Không có rate limit, có thể spam email tới nạn nhân và tạo token vô hạn.

**Kịch bản khai thác:** Kẻ tấn công gửi danh sách email và dựa vào thông báo lỗi để xác định tài khoản tồn tại, sau đó spam reset.

**Đề xuất sửa:** Trong router.forgot_password luôn trả cùng một thông báo/redirect 303 bất kể email có tồn tại hay không (request_reset không cần trả bool cho UI). Thêm rate limit theo IP và theo email, và xử lý thời gian phản hồi đồng đều.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware hay cấu hình nào đặt X-Frame-Options hoặc CSP frame-ancestors (đã tìm toàn repo, không thấy). Ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm một middleware chung trong app factory để đặt X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /forgot-password:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu header chống clickjacking; không có middleware đặt header bảo mật.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu header chống clickjacking trên trang đăng nhập; không có middleware đặt header.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /reset-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt; trang reset-password chứa token trong form nên cần CSP chặt.

**Đề xuất sửa:** Thêm CSP (default-src 'self', frame-ancestors 'none') trong middleware chung; đặt thêm Referrer-Policy: no-referrer cho /reset-password.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /forgot-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware header bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /reset-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header nosniff trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /forgot-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /forgot-password:0`, `zap:10038:dast:GET /forgot-password:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header nosniff trong repo, áp dụng cả /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🟡 NEEDS_REVIEW · LOW · generic-api-key (gitleaks) — `app/tests/test_password_reset.py:15`

CWE-798 · độ tin cậy 0.50 · nguồn: gitleaks

**Phân tích:** Dòng bị che (redacted) nên không xác minh được nội dung. Nhiều khả năng là hằng NEW_PASSWORD dùng trong test, nhưng cần con người xác nhận không phải secret thật.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B107 (bandit)** — `app/medicare/auth/router.py:134`: `token: str = ""` chỉ là giá trị mặc định của tham số query; không phải mật khẩu cứng. Token được kiểm tra qua user_for_token.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 62.5 s · 30 lần gọi LLM · 19 lần gọi công cụ · 142669 token vào / 9713 token ra · ≈ $0.2170 · chạm giới hạn: không</sub>
