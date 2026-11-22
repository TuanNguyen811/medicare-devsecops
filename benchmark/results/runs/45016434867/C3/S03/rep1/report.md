<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `014c582`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | gitleaks | generic-api-key (gitleaks) | `app/medicare/mobile/tokens.py:17` | 0.93 |
| 🔴 TP | CRITICAL | semgrep | python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) | `app/medicare/mobile/tokens.py:43` | 0.98 |
| 🔴 TP | HIGH | semgrep | python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) | `app/medicare/mobile/tokens.py:36` | 0.93 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |
| 🟢 FP | LOW | bandit | B105 (bandit) | `app/medicare/mobile/router.py:55` | 0.90 |
| 🟢 FP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · generic-api-key (gitleaks) — `app/medicare/mobile/tokens.py:17`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.93 · nguồn: gitleaks

**Phân tích:** Dòng 17 của tokens.py (Gitleaks báo) gán JWT_SECRET là chuỗi hằng số trong mã nguồn. Bí mật này dùng để ký token HS256 ở `issue_token`. Ai đọc được repo đều biết khóa ký, vi phạm R-09 (secret chỉ đọc từ biến môi trường). Hằng số này cũng được dùng khi giải mã ở `read_token`.

**Kịch bản khai thác:** Kẻ tấn công đọc repo, lấy JWT_SECRET rồi tự ký token với sub bất kỳ (ví dụ id của ADMIN hoặc bác sĩ) và đọc bệnh án qua /api/v1/mobile.

Gộp các phát hiện: `bandit:B105:app/medicare/mobile/tokens.py:17`, `gitleaks:generic-api-key:app/medicare/mobile/tokens.py:17`

**Đề xuất sửa:** Xóa hằng JWT_SECRET khỏi tokens.py. Thêm trường jwt_secret (SecretStr) vào Settings trong medicare/config.py, đọc từ biến môi trường. Ứng dụng không khởi động nếu thiếu hoặc quá ngắn (tối thiểu 32 byte), giống cách xử lý SECRET_KEY theo R-09. Truyền secret vào issue_token/read_token từ request.app.state.settings. Xoay (rotate) secret cũ vì đã lộ trong lịch sử git.

#### 🔴 TP · CRITICAL · python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) — `app/medicare/mobile/tokens.py:43`

CWE-347 · OWASP A07 · độ tin cậy 0.98 · nguồn: semgrep

**Phân tích:** `read_token` gọi jwt.decode với `verify_signature: False`, nên chữ ký không bao giờ được kiểm tra. Bất kỳ ai cũng có thể tự tạo JWT (kể cả alg HS256 với khóa tùy ý) với sub tùy ý. Claim `sv` chỉ là số nguyên nhỏ dễ đoán (session_version), nên kiểm tra sv ở get_mobile_user không ngăn được giả mạo. Toàn bộ xác thực mobile API bị vô hiệu: kẻ tấn công mạo danh bất kỳ user nào và đọc bệnh án theo quyền của họ (ví dụ ADMIN, bác sĩ).

**Kịch bản khai thác:** Kẻ tấn công tạo JWT không cần khóa với {"sub":"<id bác sĩ>","sv":0,"exp":<tương lai>}, gửi header Authorization: Bearer và gọi /api/v1/mobile/records/{id} để đọc dữ liệu bệnh án mà không có tài khoản.

**Đề xuất sửa:** Trong read_token (tokens.py) bỏ `verify_signature: False`, giữ mặc định xác minh chữ ký, chỉ để options require/verify_exp. Giữ algorithms=[JWT_ALGORITHM] cố định. Dùng secret từ env (xem F2). Thêm test: token ký sai khóa hoặc alg=none phải trả 401.

#### 🔴 TP · HIGH · python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) — `app/medicare/mobile/tokens.py:36`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.93 · nguồn: semgrep

**Phân tích:** `jwt.encode` ký bằng JWT_SECRET là hằng số hard-code trong mã nguồn. Đây cùng nguyên nhân gốc với F2, vi phạm R-09.

**Kịch bản khai thác:** Biết khóa ký từ mã nguồn, kẻ tấn công tạo token hợp lệ cho bất kỳ người dùng nào.

**Đề xuất sửa:** Như F2: nạp secret JWT từ biến môi trường qua Settings (medicare/config.py), bắt buộc có khi khởi động, và dùng giá trị đó trong issue_token/read_token của tokens.py.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** create_app chỉ thêm các middleware Session, Metrics, CatchAllErrors, không có middleware đặt header bảo mật (X-Frame-Options / CSP frame-ancestors). Trang HTML dễ bị clickjacking. Lỗi cấu hình toàn cục, không do code mobile của PR này.

**Đề xuất sửa:** Thêm một middleware trong create_app (main.py) đặt X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff, cấu hình toàn cục (cùng F9).

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware header bảo mật toàn cục ở main.py.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F5: không có middleware đặt header chống clickjacking, trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' trong create_app (main.py).

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options: nosniff. Rủi ro thấp, cấu hình toàn cục.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm vào middleware header bảo mật trong create_app: X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu trong create_app. Lỗi cấu hình toàn cục, không thuộc code mới của PR.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware toàn cục trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F10: thiếu CSP toàn cục.

**Đề xuất sửa:** Sửa một lần bằng middleware header bảo mật toàn cục trong main.py (CSP).

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F10: thiếu CSP toàn cục.

**Đề xuất sửa:** Sửa một lần bằng middleware header bảo mật toàn cục trong main.py (CSP).

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F10: thiếu CSP toàn cục.

**Đề xuất sửa:** Sửa một lần bằng middleware header bảo mật toàn cục trong main.py (CSP).

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F10: thiếu CSP toàn cục.

**Đề xuất sửa:** Sửa một lần bằng middleware header bảo mật toàn cục trong main.py (CSP).

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **B105 (bandit)** — `app/medicare/mobile/router.py:55`: Bandit B105 nhầm trường `token_type` (giá trị chuỗi "bearer" theo test) là mật khẩu hard-code. Đó là nhãn loại token OAuth, không phải secret. Token thật được sinh động bởi issue_token.
- **10021 (zap)** — `dast:GET /health:0`: /health chỉ trả JSON hằng số {"status":"ok"}, không có nội dung người dùng kiểm soát nên MIME sniffing không khai thác được. Tác động thực tế không đáng kể (header vẫn nên có qua middleware toàn cục, đã xử lý ở F6/F9).

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 54.8 s · 16 lần gọi LLM · 15 lần gọi công cụ · 96662 token vào / 8808 token ra · ≈ $0.2971 · chạm giới hạn: không</sub>
