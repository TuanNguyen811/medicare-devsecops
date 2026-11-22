<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `4c8160d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Token đặt lại mật khẩu không hết hạn và dùng lại được nhiều lần | `app/medicare/auth/reset.py:47` | 0.95 |
| 🔴 TP | MEDIUM | agent | /forgot-password tiết lộ email có tồn tại hay không (user enumeration) | `app/medicare/auth/router.py:124` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /forgot-password:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /reset-password:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /forgot-password:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /reset-password:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /forgot-password:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.55 |
| 🟡 NEEDS_REVIEW | LOW | gitleaks | generic-api-key (gitleaks) | `app/tests/test_password_reset.py:15` | 0.70 |
| 🟢 FP | LOW | bandit | B107 (bandit) | `app/medicare/auth/router.py:134` | 0.95 |

### Chi tiết

#### 🔴 TP · HIGH · Token đặt lại mật khẩu không hết hạn và dùng lại được nhiều lần — `app/medicare/auth/reset.py:47`

CWE-640 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** RESET_TOKEN_TTL được định nghĩa nhưng user_for_token không kiểm tra created_at; token cũng không bị xóa/đánh dấu đã dùng sau reset_password. Do đó link hợp lệ vĩnh viễn và dùng được nhiều lần, vi phạm R-18 (một lần, hết hạn 15 phút). Khi bị lộ (log, lịch sử mail) kẻ tấn công chiếm tài khoản bất cứ lúc nào.

**Kịch bản khai thác:** Kẻ tấn công có được email/link reset cũ (đã dùng hoặc quá 15 phút) vẫn mở /reset-password?token=... và đặt mật khẩu mới, chiếm tài khoản.

**Đề xuất sửa:** Trong reset.user_for_token so sánh created_at với thời điểm hiện tại trừ RESET_TOKEN_TTL và từ chối token quá hạn. Trong reset.reset_password xóa token vừa dùng (và mọi token khác của user_id) trong cùng transaction để chỉ dùng một lần. Nên xóa token quá hạn định kỳ.

#### 🔴 TP · MEDIUM · /forgot-password tiết lộ email có tồn tại hay không (user enumeration) — `app/medicare/auth/router.py:124`

CWE-204 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Khi email không có tài khoản, server trả trang lỗi "Không tìm thấy tài khoản..." còn khi có thì redirect 303 kèm flash. Phản hồi khác nhau cho phép dò email nhân viên/bệnh nhân, vi phạm R-18 (và R-07). Endpoint công khai, không có giới hạn tần suất.

**Kịch bản khai thác:** Kẻ tấn công gửi hàng loạt email vào /forgot-password và phân biệt phản hồi để liệt kê email hợp lệ phục vụ phishing hoặc tấn công tiếp.

**Đề xuất sửa:** Trong router.forgot_password luôn trả cùng một phản hồi (cùng redirect 303 /login và cùng thông báo flash, kiểu 'Nếu email tồn tại, chúng tôi đã gửi liên kết') bất kể request_reset trả True hay False; không dùng kết quả để phân nhánh phản hồi. Nên thêm giới hạn tần suất theo IP/email.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP quan sát động thấy thiếu X-Frame-Options/frame-ancestors. Trang có form (đăng nhập, đổi mật khẩu) có thể bị clickjacking.

**Đề xuất sửa:** Thêm middleware toàn cục đặt header X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /forgot-password:0`

CWE-1021 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /forgot-password mới là form công khai thiếu header chống clickjacking.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking.

**Đề xuất sửa:** Middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /reset-password:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** /reset-password (trang mang token, nhập mật khẩu) không có CSP, giảm khả năng phòng thủ nhiều lớp trước XSS.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none'); thêm Referrer-Policy: no-referrer cho trang reset để token không rò qua Referer.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /forgot-password:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Response POST /forgot-password thiếu CSP.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /reset-password:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Response POST /reset-password thiếu CSP.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu nosniff trên GET /; mức thấp.

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /forgot-password:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên /forgot-password; rủi ro thấp nhưng là cấu hình thiếu.

Gộp các phát hiện: `zap:10021:dast:GET /forgot-password:0`, `zap:10038:dast:GET /forgot-password:0`

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu nosniff trên /health; rủi ro rất thấp nhưng sửa được bằng middleware chung.

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu nosniff trên /login.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff.

#### 🟡 NEEDS_REVIEW · LOW · generic-api-key (gitleaks) — `app/tests/test_password_reset.py:15`

CWE-798 · độ tin cậy 0.70 · nguồn: gitleaks

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] Dòng bị báo (dòng 15, đã bị redact) nằm trong file test, nhiều khả năng là hằng NEW_PASSWORD dùng làm mật khẩu thử, không phải secret thật. File chỉ chạy trong pytest.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B107 (bandit)** — `app/medicare/auth/router.py:134`: Giá trị '' là mặc định rỗng của tham số query `token`, không phải mật khẩu hard-code.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 43.7 s · 16 lần gọi LLM · 15 lần gọi công cụ · 80409 token vào / 6566 token ra · ≈ $0.2362 · chạm giới hạn: không</sub>
