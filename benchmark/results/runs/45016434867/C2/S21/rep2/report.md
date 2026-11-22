<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `4c8160d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Token đặt lại mật khẩu không hết hạn và dùng lại được nhiều lần | `app/medicare/auth/reset.py:47` | 0.95 |
| 🔴 TP | MEDIUM | agent | Liệt kê tài khoản (user enumeration) qua /forgot-password | `app/medicare/auth/router.py:123` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /forgot-password:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /reset-password:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /forgot-password:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /reset-password:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /forgot-password:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🟢 FP | LOW | bandit | B107 (bandit) | `app/medicare/auth/router.py:134` | 0.95 |
| 🟢 FP | LOW | gitleaks | generic-api-key (gitleaks) | `app/tests/test_password_reset.py:15` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Token đặt lại mật khẩu không hết hạn và dùng lại được nhiều lần — `app/medicare/auth/reset.py:47`

CWE-640 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** RESET_TOKEN_TTL được định nghĩa nhưng user_for_token không kiểm tra created_at. reset_password cũng không xóa/đánh dấu đã dùng token. Token vì vậy có hiệu lực vĩnh viễn và dùng được nhiều lần, vi phạm R-18 (một lần, 15 phút). Các token cũ của cùng user cũng không bị vô hiệu khi yêu cầu token mới hoặc sau khi đổi mật khẩu.

**Kịch bản khai thác:** Kẻ có được link cũ (lịch sử trình duyệt, mail forward, log proxy) nhiều tuần sau vẫn đặt lại được mật khẩu và chiếm tài khoản, kể cả sau khi chủ tài khoản đã dùng link đó.

**Đề xuất sửa:** Trong reset.user_for_token, từ chối token khi now - reset.created_at > RESET_TOKEN_TTL. Trong reset.reset_password (hoặc router.reset_password) xóa token vừa dùng và toàn bộ PasswordResetToken khác của user trong cùng transaction để token chỉ dùng một lần. Nên xóa cả token cũ khi request_reset tạo token mới.

#### 🔴 TP · MEDIUM · Liệt kê tài khoản (user enumeration) qua /forgot-password — `app/medicare/auth/router.py:123`

CWE-204 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Khi email không tồn tại, server trả 200 kèm lỗi "Không tìm thấy tài khoản..."; khi tồn tại trả 303 redirect. Phản hồi khác nhau, vi phạm R-18/R-07. Endpoint công khai và không có giới hạn tần suất, nên có thể dò email nhân viên/bệnh nhân hàng loạt hoặc spam mail.

**Kịch bản khai thác:** Kẻ tấn công gửi danh sách email tới /forgot-password và dựa vào phản hồi để biết email nào thuộc tài khoản MediCare, phục vụ phishing hoặc tấn công tiếp.

**Đề xuất sửa:** Trong router.forgot_password luôn trả cùng một phản hồi (cùng status, redirect /login và cùng thông báo flash) dù email có tồn tại hay không; bỏ thông báo lỗi 'Không tìm thấy tài khoản'. Giữ thời gian xử lý tương đương và cân nhắc giới hạn tần suất theo IP/email.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không đặt header bảo mật nào (không có X-Frame-Options, CSP frame-ancestors, nosniff); search_code không thấy, main.py chỉ có các middleware Session/CatchAll/Metrics.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /forgot-password:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu chống clickjacking; không có middleware đặt header bảo mật trong main.py.

**Đề xuất sửa:** Thêm middleware toàn cục trong app/medicare/main.py đặt X-Frame-Options: DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang login có thể bị nhúng iframe; ứng dụng không đặt X-Frame-Options/CSP.

**Đề xuất sửa:** Thêm middleware toàn cục trong app/medicare/main.py đặt X-Frame-Options: DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /reset-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt; trang reset-password chứa token trong form nên cần CSP chặt.

**Đề xuất sửa:** Thêm Content-Security-Policy (default-src 'self', frame-ancestors 'none') qua middleware toàn cục trong app/medicare/main.py; cân nhắc Referrer-Policy: no-referrer cho /reset-password vì token nằm trong URL.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /forgot-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /reset-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header nosniff trong ứng dụng.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /forgot-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /forgot-password:0`, `zap:10038:dast:GET /forgot-password:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header nosniff trong ứng dụng, kể cả /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header nosniff trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware toàn cục trong app/medicare/main.py.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **B107 (bandit)** — `app/medicare/auth/router.py:134`: `token: str = ""` là giá trị mặc định của query param, không phải mật khẩu cứng. Token rỗng bị user_for_token từ chối.
- **generic-api-key (gitleaks)** — `app/tests/test_password_reset.py:15`: Dòng bị Gitleaks báo nằm trong file test và là hằng số NEW_PASSWORD, mật khẩu giả dùng cho test, không phải secret thật. Giá trị không thể xem (đã bị che) nhưng cách dùng trong test cho thấy đó là mật khẩu thử.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 50.4 s · 21 lần gọi LLM · 20 lần gọi công cụ · 153983 token vào / 7426 token ra · ≈ $0.1279 · chạm giới hạn: không</sub>
