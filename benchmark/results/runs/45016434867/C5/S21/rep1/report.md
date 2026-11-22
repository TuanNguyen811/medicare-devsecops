<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `4c8160d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Token đặt lại mật khẩu không hết hạn và dùng được nhiều lần | `app/medicare/auth/reset.py:50` | 0.95 |
| 🔴 TP | MEDIUM | agent | Liệt kê tài khoản qua /forgot-password (phản hồi khác nhau) | `app/medicare/auth/router.py:122` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /forgot-password:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /reset-password:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /forgot-password:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /reset-password:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /forgot-password:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.75 |
| 🟢 FP | LOW | bandit | B107 (bandit) | `app/medicare/auth/router.py:134` | 0.90 |
| 🟢 FP | LOW | gitleaks | generic-api-key (gitleaks) | `app/tests/test_password_reset.py:15` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Token đặt lại mật khẩu không hết hạn và dùng được nhiều lần — `app/medicare/auth/reset.py:50`

CWE-640 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** RESET_TOKEN_TTL được khai báo nhưng chỉ dùng để in số phút trong email; user_for_token không kiểm tra created_at. reset_password() không xóa/đánh dấu token đã dùng, nên token còn hiệu lực vĩnh viễn và dùng lại được nhiều lần. Vi phạm R-18 (một lần, hết hạn 15 phút).

**Kịch bản khai thác:** Kẻ có được link cũ (lịch sử trình duyệt, log proxy, email cũ) vài tháng sau vẫn đặt lại được mật khẩu và chiếm tài khoản.

**Đề xuất sửa:** Trong reset.user_for_token, từ chối token có created_at cũ hơn RESET_TOKEN_TTL (so sánh với thời gian hiện tại UTC). Thêm cột used_at hoặc xóa bản ghi PasswordResetToken trong reset.reset_password (cùng transaction) để token chỉ dùng một lần; khi tạo token mới nên vô hiệu hóa các token cũ của user. Bổ sung migration nếu thêm cột và test cho hết hạn/tái sử dụng.

#### 🔴 TP · MEDIUM · Liệt kê tài khoản qua /forgot-password (phản hồi khác nhau) — `app/medicare/auth/router.py:122`

CWE-204 · OWASP A07 · vi phạm R-18 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Khi email không tồn tại, endpoint trả trang lỗi "Không tìm thấy tài khoản nào đăng ký với email này"; khi tồn tại thì redirect 303 kèm flash. Không có xác thực hay rate limit nên kẻ tấn công dò được email nhân viên/bệnh nhân (PII). Vi phạm R-18 và R-07.

**Kịch bản khai thác:** Kẻ tấn công thử danh sách email và phân biệt email hợp lệ qua thông báo lỗi để phục vụ phishing/tấn công mục tiêu.

**Đề xuất sửa:** Trong router.forgot_password, luôn trả cùng một phản hồi (flash thông báo chung 'Nếu email tồn tại, liên kết đã được gửi' + redirect 303 /login) bất kể request_reset trả True hay False; không báo lỗi riêng cho email không tồn tại. Cân nhắc rate limit theo IP/email.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không có middleware/đặt header bảo mật nào (search không thấy X-Frame-Options/CSP/nosniff), nên trang đăng nhập/đặt lại mật khẩu có thể bị clickjacking.

**Đề xuất sửa:** Thêm một middleware trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /forgot-password:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong toàn app.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong app/medicare/main.py (X-Frame-Options DENY / frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong toàn app.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong app/medicare/main.py (X-Frame-Options DENY / frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /reset-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** App không đặt Content-Security-Policy ở đâu cả; trang reset-password chứa token trong form nên cần CSP.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware header bảo mật ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /forgot-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** App không đặt Content-Security-Policy.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /reset-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** App không đặt Content-Security-Policy.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options trong app.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung ở app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /forgot-password:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options trong app.

Gộp các phát hiện: `zap:10021:dast:GET /forgot-password:0`, `zap:10038:dast:GET /forgot-password:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options trong app (kể cả /health).

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung ở app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options trong app.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung ở app/medicare/main.py.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **B107 (bandit)** — `app/medicare/auth/router.py:134`: Giá trị mặc định token="" là tham số query rỗng, không phải mật khẩu; rỗng bị từ chối bởi user_for_token.
- **generic-api-key (gitleaks)** — `app/tests/test_password_reset.py:15`: Dòng 15 trong file test là hằng NEW_PASSWORD (mật khẩu mẫu cho test, dùng trong set_password), không phải secret thật; chỉ chạy trong test.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 44.1 s · 22 lần gọi LLM · 21 lần gọi công cụ · 153462 token vào / 6636 token ra · ≈ $0.1868 · chạm giới hạn: không</sub>
