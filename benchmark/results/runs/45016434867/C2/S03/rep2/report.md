<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 13 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `014c582`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | semgrep | python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) | `app/medicare/mobile/tokens.py:43` | 0.97 |
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/mobile/tokens.py:17` | 0.90 |
| 🔴 TP | HIGH | semgrep | python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) | `app/medicare/mobile/tokens.py:36` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🟢 FP | LOW | bandit | B105 (bandit) | `app/medicare/mobile/router.py:55` | 0.90 |

### Chi tiết

#### 🔴 TP · CRITICAL · python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) — `app/medicare/mobile/tokens.py:43`

CWE-347 · OWASP A07 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** read_token gọi jwt.decode với verify_signature False nên chữ ký không được kiểm tra. Bất kỳ ai cũng tự tạo token với sub bất kỳ và sv khớp (sv dễ đoán) để đăng nhập thành người khác. Đây là bypass xác thực hoàn toàn.

**Kịch bản khai thác:** Kẻ tấn công tạo JWT không ký (alg HS256, chữ ký rác) với sub=id bác sĩ, sv=0, exp tương lai; gửi Bearer và đọc mọi bệnh án qua /api/v1/mobile/records/*.

**Đề xuất sửa:** Trong read_token (tokens.py) bỏ verify_signature=False để PyJWT xác minh chữ ký bằng khóa từ môi trường, giữ algorithms=[HS256], verify_exp và require. Thêm test token giả/sai chữ ký phải trả 401.

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/mobile/tokens.py:17`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** JWT_SECRET được hard-code trong tokens.py (dòng 17) và nằm trong mã nguồn/git; vi phạm R-09 (secret chỉ đọc từ biến môi trường).

**Kịch bản khai thác:** Ai đọc được repo biết khóa HS256 và tự ký token cho bất kỳ user id nào (kể cả ADMIN/bác sĩ), truy cập bệnh án.

Gộp các phát hiện: `bandit:B105:app/medicare/mobile/tokens.py:17`, `gitleaks:generic-api-key:app/medicare/mobile/tokens.py:17`

**Đề xuất sửa:** Xóa hằng JWT_SECRET khỏi tokens.py; đọc khóa riêng từ biến môi trường qua medicare.config.Settings (không khởi động nếu thiếu/yếu, như SECRET_KEY). Xoay (rotate) khóa cũ vì đã lộ trong lịch sử git.

#### 🔴 TP · HIGH · python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) — `app/medicare/mobile/tokens.py:36`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** issue_token ký JWT bằng JWT_SECRET hard-code; cùng gốc với F2, vi phạm R-09.

**Kịch bản khai thác:** Kẻ tấn công dùng secret trong mã nguồn để giả mạo token hợp lệ.

**Đề xuất sửa:** Trong issue_token và read_token dùng khóa lấy từ Settings (biến môi trường) thay cho hằng trong mã; rotate khóa.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy middleware nào đặt X-Frame-Options / CSP frame-ancestors; ứng dụng dễ bị clickjacking.

**Đề xuất sửa:** Thêm middleware security headers trong create_app (main.py) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; không có middleware đặt header trong repo.

**Đề xuất sửa:** Dùng middleware security headers chung trong main.py (X-Frame-Options DENY, CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') qua middleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options; không có middleware đặt header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers (main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; tác động thấp nhưng sửa chung bằng middleware.

**Đề xuất sửa:** Middleware security headers chung trong main.py thêm nosniff cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ·main.py.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B105 (bandit)** — `app/medicare/mobile/router.py:55`: "token_type" là nhãn loại token OAuth ("bearer"), không phải mật khẩu; bandit B105 nhầm do tên khóa chứa "token".

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 49.8 s · 20 lần gọi LLM · 19 lần gọi công cụ · 125738 token vào / 6383 token ra · ≈ $0.1100 · chạm giới hạn: không</sub>
