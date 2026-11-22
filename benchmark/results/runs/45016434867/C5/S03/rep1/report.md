<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 13 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `014c582`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | semgrep | python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) | `app/medicare/mobile/tokens.py:43` | 0.97 |
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/mobile/tokens.py:17` | 0.90 |
| 🔴 TP | HIGH | semgrep | python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) | `app/medicare/mobile/tokens.py:36` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🟢 FP | LOW | bandit | B105 (bandit) | `app/medicare/mobile/router.py:55` | 0.90 |

### Chi tiết

#### 🔴 TP · CRITICAL · python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) — `app/medicare/mobile/tokens.py:43`

CWE-347 · OWASP A07 · vi phạm R-01 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** read_token đặt verify_signature=False nên chữ ký không được kiểm tra: mọi token tự tạo đều được chấp nhận. get_mobile_user tin claims sub và sv, nên chỉ cần biết id user là mạo danh được bất kỳ ai, kể cả bác sĩ, và đọc bệnh án mà không cần secret.

**Kịch bản khai thác:** Kẻ tấn công tạo JWT với sub=1, sv=0, exp tương lai, ký tùy ý, gọi /api/v1/mobile/records/{id} và đọc dữ liệu bệnh án.

**Đề xuất sửa:** Xóa verify_signature=False trong read_token (tokens.py) để PyJWT luôn kiểm tra chữ ký; giữ algorithms cố định và require exp/sub. Thêm test: token ký sai khóa phải trả 401.

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/mobile/tokens.py:17`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** JWT_SECRET được hard-code trong tokens.py:17 (Gitleaks và Bandit cùng báo). Ai đọc được mã nguồn đều ký được token hợp lệ. Vi phạm R-09: secret chỉ đọc từ biến môi trường.

**Kịch bản khai thác:** Kẻ tấn công lấy secret từ repo, tự ký JWT với sub của ADMIN/bác sĩ rồi đọc bệnh án.

Gộp các phát hiện: `bandit:B105:app/medicare/mobile/tokens.py:17`, `gitleaks:generic-api-key:app/medicare/mobile/tokens.py:17`

**Đề xuất sửa:** Xóa secret khỏi mã nguồn, đọc từ biến môi trường qua Settings trong medicare/config.py (như SECRET_KEY), không khởi động nếu thiếu hoặc quá ngắn. Xoay (rotate) secret đã lộ trong git history.

#### 🔴 TP · HIGH · python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) — `app/medicare/mobile/tokens.py:36`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** issue_token/read_token dùng JWT_SECRET hard-code để ký/giải mã (cùng nguyên nhân với F2).

**Kịch bản khai thác:** Như F2: giả mạo token bằng secret lộ trong mã nguồn.

**Đề xuất sửa:** Truyền secret lấy từ cấu hình/biến môi trường vào issue_token và read_token thay cho hằng trong mã nguồn.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không thấy mã Python nào đặt X-Frame-Options/CSP/X-Content-Type-Options, nên thiếu header bảo mật là thật (cấu hình chung, không riêng PR).

**Đề xuất sửa:** Thêm middleware trong create_app (main.py) đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Như F5: không có header chống clickjacking trong ứng dụng.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options/frame-ancestors trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không thấy X-Content-Type-Options trong mã ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong mã ứng dụng.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt (default-src 'self') trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong mã ứng dụng.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong mã ứng dụng.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong mã ứng dụng.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong mã ứng dụng.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không thấy X-Content-Type-Options trong mã ứng dụng.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không thấy X-Content-Type-Options trong mã ứng dụng (kể cả /health).

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff trong main.py.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B105 (bandit)** — `app/medicare/mobile/router.py:55`: Bandit B105 bị kích hoạt bởi khóa "token_type"; giá trị là hằng loại token OAuth ("bearer", test xác nhận), không phải mật khẩu. Token thật được sinh bởi issue_token.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 67.5 s · 34 lần gọi LLM · 20 lần gọi công cụ · 147445 token vào / 11576 token ra · ≈ $0.2479 · chạm giới hạn: không</sub>
