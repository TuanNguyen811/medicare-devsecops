<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `4c8160d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Token đặt lại mật khẩu không hết hạn và không dùng một lần | `app/medicare/auth/reset.py:50` | 0.95 |
| 🔴 TP | MEDIUM | agent | Liệt kê tài khoản qua phản hồi quên mật khẩu khác nhau | `app/medicare/auth/router.py:123` | 0.95 |
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
| 🟢 FP | LOW | bandit | B107 (bandit) | `app/medicare/auth/router.py:134` | 0.90 |
| 🟢 FP | LOW | gitleaks | generic-api-key (gitleaks) | `app/tests/test_password_reset.py:15` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Token đặt lại mật khẩu không hết hạn và không dùng một lần — `app/medicare/auth/reset.py:50`

CWE-613 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** RESET_TOKEN_TTL được định nghĩa nhưng chỉ dùng để in số phút trong email. user_for_token không so sánh created_at với thời gian hiện tại, và reset_password không xóa hoặc đánh dấu token đã dùng. Vì vậy token có hiệu lực vô thời hạn và dùng được nhiều lần. Điều này vi phạm R-18 (một lần, hết hạn sau 15 phút).

**Kịch bản khai thác:** Kẻ tấn công lấy được link cũ (lịch sử trình duyệt, mailbox bị lộ) từ nhiều ngày trước, hoặc dùng lại link đã dùng, để đặt lại mật khẩu và chiếm tài khoản.

**Đề xuất sửa:** Trong reset.user_for_token, từ chối token có created_at cũ hơn RESET_TOKEN_TTL (15 phút). Trong reset.reset_password, xóa token vừa dùng (và mọi token khác của user) trong cùng transaction để chỉ dùng một lần. Khi tạo token mới trong request_reset, nên xóa token cũ của user.

#### 🔴 TP · MEDIUM · Liệt kê tài khoản qua phản hồi quên mật khẩu khác nhau — `app/medicare/auth/router.py:123`

CWE-204 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** POST /forgot-password trả lỗi "Không tìm thấy tài khoản nào đăng ký với email này" khi email không tồn tại, còn nếu có thì redirect 303. Phản hồi khác nhau cho phép dò email nhân viên và bệnh nhân. Điều này vi phạm R-18 và R-07. Endpoint cũng không giới hạn tốc độ.

**Kịch bản khai thác:** Kẻ tấn công thử danh sách email và dựa vào thông báo lỗi để xác định ai có tài khoản trong hệ thống bệnh viện.

**Đề xuất sửa:** Trong router.forgot_password luôn trả cùng một phản hồi (flash thông báo chung rồi redirect /login 303) dù email có tồn tại hay không, và bỏ thông báo lỗi riêng. Nên đồng bộ thời gian xử lý giữa hai nhánh và thêm giới hạn tốc độ cho endpoint.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong code Python không thấy middleware nào đặt X-Frame-Options, CSP frame-ancestors, X-Content-Type-Options. Trang bị nhúng iframe, nguy cơ clickjacking.

**Đề xuất sửa:** Thêm một middleware chung trong app factory để đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /forgot-password:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong app.

**Đề xuất sửa:** Dùng middleware header bảo mật chung: X-Frame-Options DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang đăng nhập không có header chống clickjacking.

**Đề xuất sửa:** Dùng middleware header bảo mật chung: X-Frame-Options DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /reset-password:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào. Trang /reset-password nhận token qua query string nên cần CSP chặt, kèm Referrer-Policy no-referrer.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt trong middleware header bảo mật chung, và Referrer-Policy: no-referrer cho trang reset-password.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /forgot-password:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong app.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /reset-password:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong app.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, app không đặt header này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /forgot-password:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên mọi response vì app không có middleware đặt header này.

Gộp các phát hiện: `zap:10021:dast:GET /forgot-password:0`, `zap:10038:dast:GET /forgot-password:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, app không đặt header này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, app không đặt header này.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **B107 (bandit)** — `app/medicare/auth/router.py:134`: Giá trị mặc định rỗng của tham số token là giá trị mặc định của query param, không phải mật khẩu cứng. Chuỗi rỗng bị user_for_token từ chối.
- **generic-api-key (gitleaks)** — `app/tests/test_password_reset.py:15`: Dòng bị Gitleaks báo nằm trong file test và đã bị ẩn. Nó gần như chắc chắn là hằng NEW_PASSWORD của test (mật khẩu mẫu), không phải secret thật. Code chỉ chạy trong test.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 39.3 s · 19 lần gọi LLM · 18 lần gọi công cụ · 100754 token vào / 6212 token ra · ≈ $0.1024 · chạm giới hạn: không</sub>
