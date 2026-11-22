<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 13 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `014c582`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | semgrep | python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) | `app/medicare/mobile/tokens.py:43` | 0.98 |
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/mobile/tokens.py:17` | 0.90 |
| 🔴 TP | HIGH | semgrep | python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) | `app/medicare/mobile/tokens.py:36` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |
| 🟢 FP | LOW | bandit | B105 (bandit) | `app/medicare/mobile/router.py:55` | 0.95 |

### Chi tiết

#### 🔴 TP · CRITICAL · python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) — `app/medicare/mobile/tokens.py:43`

CWE-347 · OWASP A07 · độ tin cậy 0.98 · nguồn: semgrep

**Phân tích:** read_token gọi jwt.decode với verify_signature=False nên chữ ký không được kiểm tra. Kẻ tấn công tự tạo token với sub bất kỳ (kể cả admin), sv=session_version đoán được, và exp hợp lệ để chiếm quyền bất kỳ user, truy cập hồ sơ bệnh án.

**Kịch bản khai thác:** Tạo JWT không cần khóa với {sub: <id admin>, sv: 0, exp: tương lai}, gửi Authorization: Bearer; get_mobile_user chấp nhận.

**Đề xuất sửa:** Trong read_token bỏ verify_signature=False (để mặc định xác minh chữ ký), giữ algorithms=[JWT_ALGORITHM] và require [sub, exp, sv]; dùng secret từ Settings. Thêm test token giả/không chữ ký bị 401.

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/mobile/tokens.py:17`

CWE-798 · OWASP A04 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** JWT_SECRET được hard-code trong source (tokens.py:17, Gitleaks phát hiện). Ai đọc được repo đều có thể ký token hợp lệ cho bất kỳ user nào.

Gộp các phát hiện: `bandit:B105:app/medicare/mobile/tokens.py:17`, `gitleaks:generic-api-key:app/medicare/mobile/tokens.py:17`

**Đề xuất sửa:** Xoá secret khỏi tokens.py; thêm trường jwt_secret vào medicare.config.Settings, đọc từ biến môi trường/secret manager (ngẫu nhiên ≥32 byte), fail-fast khi thiếu. Xoay (rotate) secret đã bị lộ trong lịch sử git.

#### 🔴 TP · HIGH · python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) — `app/medicare/mobile/tokens.py:36`

CWE-798 · OWASP A04 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** issue_token ký JWT bằng JWT_SECRET hard-code, cùng nguyên nhân với F2.

**Đề xuất sửa:** Nạp secret từ Settings/biến môi trường thay vì hằng số trong source; rotate secret hiện tại.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy middleware đặt X-Frame-Options/CSP/nosniff; thiếu header trên toàn ứng dụng (không riêng PR).

**Đề xuất sửa:** Thêm middleware trong create_app (medicare/main.py) đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F5: không có header chống clickjacking trong code.

**Đề xuất sửa:** Dùng middleware security headers chung trong medicare/main.py (X-Frame-Options/frame-ancestors).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP được đặt ở bất kỳ đâu trong code.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers ở medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong code.

**Đề xuất sửa:** Thêm CSP qua middleware chung ở medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong code.

**Đề xuất sửa:** Thêm CSP qua middleware chung ở medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong code.

**Đề xuất sửa:** Thêm CSP qua middleware chung ở medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong code.

**Đề xuất sửa:** Thêm CSP qua middleware chung ở medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu nosniff toàn ứng dụng.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu nosniff toàn ứng dụng, gồm /health.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở medicare/main.py.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B105 (bandit)** — `app/medicare/mobile/router.py:55`: Giá trị được báo là "token_type" của OAuth ("bearer"), không phải mật khẩu; access_token được sinh động.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 40.6 s · 22 lần gọi LLM · 21 lần gọi công cụ · 87727 token vào / 6425 token ra · ≈ $0.1439 · chạm giới hạn: không</sub>
