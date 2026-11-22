<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `4c8160d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Token đặt lại mật khẩu không hết hạn sau 15 phút và dùng được nhiều lần | `app/medicare/auth/reset.py:48` | 0.95 |
| 🔴 TP | MEDIUM | agent | Liệt kê tài khoản qua phản hồi khác nhau của /forgot-password | `app/medicare/auth/router.py:123` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /forgot-password:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /forgot-password:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /reset-password:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /forgot-password:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /reset-password:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🟢 FP | LOW | bandit | B107 (bandit) | `app/medicare/auth/router.py:134` | 0.90 |
| 🟢 FP | LOW | gitleaks | generic-api-key (gitleaks) | `app/tests/test_password_reset.py:15` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Token đặt lại mật khẩu không hết hạn sau 15 phút và dùng được nhiều lần — `app/medicare/auth/reset.py:48`

CWE-613 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** RESET_TOKEN_TTL được khai báo nhưng chỉ dùng để in số phút trong email. user_for_token không kiểm tra created_at, và reset_password không xóa hay đánh dấu token đã dùng. Vì vậy liên kết có hiệu lực vô thời hạn và dùng lại được, trái với R-18.

**Kịch bản khai thác:** Kẻ tấn công lấy được một email hoặc log cũ chứa liên kết reset, ngay cả vài tuần sau, rồi đặt lại mật khẩu và chiếm tài khoản. Liên kết đã dùng vẫn dùng lại được.

**Đề xuất sửa:** Trong reset.py::user_for_token, từ chối token có created_at cũ hơn RESET_TOKEN_TTL (so sánh với thời gian hiện tại). Trong reset_password và router.reset_password, xóa token vừa dùng, đồng thời xóa mọi token còn lại của user trong cùng transaction để token chỉ dùng một lần. Cũng nên vô hiệu token cũ khi cấp token mới.

#### 🔴 TP · MEDIUM · Liệt kê tài khoản qua phản hồi khác nhau của /forgot-password — `app/medicare/auth/router.py:123`

CWE-204 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Khi email không tồn tại, server trả form kèm lỗi "Không tìm thấy tài khoản nào đăng ký với email này". Khi tồn tại, server trả 303 về /login. Hai phản hồi khác nhau cho phép dò email nhân viên và bệnh nhân. R-18 yêu cầu phản hồi giống hệt nhau. Endpoint cũng không giới hạn tần suất.

**Kịch bản khai thác:** Kẻ tấn công thử danh sách email và phân biệt email hợp lệ qua thông báo lỗi hoặc redirect, từ đó phục vụ phishing và tấn công có mục tiêu.

**Đề xuất sửa:** Trong router.forgot_password, luôn trả cùng một phản hồi (cùng status, flash và redirect 303 về /login) dù tài khoản có tồn tại hay không, và bỏ thông báo lỗi dò được. Nên thêm giới hạn tần suất theo IP và email. Xử lý gửi mail sao cho thời gian phản hồi không lộ khác biệt.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** search_code không tìm thấy nơi nào đặt X-Frame-Options, nosniff hay CSP trong ứng dụng. Header bị thiếu trên toàn app, nên có nguy cơ clickjacking.

**Đề xuất sửa:** Thêm middleware dùng chung (trong app factory) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none', X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /forgot-password:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào được đặt trong app.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options/CSP frame-ancestors cho mọi response, gồm cả /forgot-password.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /forgot-password:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong code của app.

Gộp các phát hiện: `zap:10021:dast:GET /forgot-password:0`, `zap:10038:dast:GET /forgot-password:0`

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang đăng nhập có thể bị nhúng vào iframe vì app không đặt header chống clickjacking.

**Đề xuất sửa:** Middleware chung đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /reset-password:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt. Trang reset-password nhận token qua URL nên càng cần CSP.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt (default-src 'self'). Trang reset-password nên thêm Referrer-Policy: no-referrer để token trong URL không lộ qua Referer.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /forgot-password:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu CSP trên toàn app.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /reset-password:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu CSP trên toàn app.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app, gồm cả /health.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **B107 (bandit)** — `app/medicare/auth/router.py:134`: Giá trị mặc định rỗng của tham số `token` là mặc định của tham số Form/Query, không phải mật khẩu hard-code. Giá trị rỗng bị từ chối bởi user_for_token.
- **generic-api-key (gitleaks)** — `app/tests/test_password_reset.py:15`: Dòng bị báo nằm trong file test và đã bị ẩn. Từ cách dùng, đó là hằng NEW_PASSWORD, một mật khẩu mẫu dùng trong test, không phải secret thật.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 42.1 s · 19 lần gọi LLM · 18 lần gọi công cụ · 125901 token vào / 6330 token ra · ≈ $0.1735 · chạm giới hạn: không</sub>
