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
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🟢 FP | LOW | bandit | B105 (bandit) | `app/medicare/mobile/router.py:55` | 0.90 |

### Chi tiết

#### 🔴 TP · CRITICAL · python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) — `app/medicare/mobile/tokens.py:43`

CWE-347 · OWASP A07 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** read_token gọi jwt.decode với options verify_signature=False nên không kiểm tra chữ ký. Kẻ tấn công tự tạo token với sub bất kỳ (kể cả admin/bác sĩ) và sv=0 hoặc giá trị đoán được để mạo danh. Từ đó đọc bệnh án, vi phạm R-01/R-02.

**Kịch bản khai thác:** Tạo JWT không ký (alg HS256 với chữ ký tùy ý), sub=id nạn nhân, sv khớp session_version, exp tương lai. Gọi /api/v1/mobile/records/{id} để đọc bệnh án.

**Đề xuất sửa:** Trong app/medicare/mobile/tokens.py, hàm read_token: bỏ verify_signature=False, để PyJWT xác minh chữ ký bằng secret từ môi trường, giữ algorithms=[HS256] và require exp/sub. Thêm test token giả mạo bị 401.

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/mobile/tokens.py:17`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** JWT_SECRET bị hard-code trong tokens.py:17 (Gitleaks và Bandit cùng báo). Ai đọc được mã nguồn đều có thể ký token hợp lệ. Vi phạm R-09: secret chỉ đọc từ biến môi trường.

Gộp các phát hiện: `bandit:B105:app/medicare/mobile/tokens.py:17`, `gitleaks:generic-api-key:app/medicare/mobile/tokens.py:17`

**Đề xuất sửa:** Bỏ giá trị hard-code trong app/medicare/mobile/tokens.py. Đọc secret JWT từ Settings (biến môi trường) như SECRET_KEY, và không khởi động nếu thiếu hoặc quá yếu. Đổi (rotate) secret đã lộ trong git history.

#### 🔴 TP · HIGH · python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) — `app/medicare/mobile/tokens.py:36`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** issue_token ký JWT bằng JWT_SECRET hard-code, cùng nguyên nhân với F2. Kẻ tấn công có thể tự tạo token cho bất kỳ user.

**Đề xuất sửa:** Trong tokens.py, issue_token và read_token phải dùng secret nạp từ cấu hình/biến môi trường, không dùng hằng số trong mã.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** search_code không tìm thấy X-Frame-Options hay CSP trong app, nên trang HTML thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong toàn bộ app, kể cả /login.

**Đề xuất sửa:** Dùng middleware chung trong main.py thêm X-Frame-Options/CSP frame-ancestors.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** App chưa đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self') qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** App chưa đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** App chưa đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** App chưa đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** App chưa đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trong toàn app.

**Đề xuất sửa:** Middleware chung trong main.py thêm nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu nosniff trên /health, cùng nguyên nhân thiếu header chung.

**Đề xuất sửa:** Middleware chung trong main.py thêm nosniff cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không thấy X-Content-Type-Options: nosniff ở đâu trong app.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung trong main.py thêm X-Content-Type-Options: nosniff.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B105 (bandit)** — `app/medicare/mobile/router.py:55`: Bandit B105 khớp nhầm khóa "token_type" với password. Giá trị chỉ là loại token OAuth ("bearer", test xác nhận), không phải bí mật.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 40.0 s · 19 lần gọi LLM · 18 lần gọi công cụ · 59028 token vào / 6149 token ra · ≈ $0.1460 · chạm giới hạn: không</sub>
