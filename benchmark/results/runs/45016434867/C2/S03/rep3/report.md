<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 3 lỗi thật (TP) · 10 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `014c582`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | semgrep | python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) | `app/medicare/mobile/tokens.py:43` | 0.98 |
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/mobile/tokens.py:17` | 0.90 |
| 🔴 TP | HIGH | semgrep | python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) | `app/medicare/mobile/tokens.py:36` | 0.90 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.50 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.50 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🟢 FP | LOW | bandit | B105 (bandit) | `app/medicare/mobile/router.py:55` | 0.95 |

### Chi tiết

#### 🔴 TP · CRITICAL · python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) — `app/medicare/mobile/tokens.py:43`

CWE-347 · OWASP A07 · vi phạm R-01 · độ tin cậy 0.98 · nguồn: semgrep

**Phân tích:** read_token gọi jwt.decode với verify_signature=False nên chữ ký không được kiểm tra. Bất kỳ ai cũng tự tạo token với sub=<id user> và sv khớp session_version (số nhỏ, đoán được) để truy cập API như user đó, kể cả bác sĩ/ADMIN. Bypass xác thực hoàn toàn, lộ bệnh án.

**Kịch bản khai thác:** Kẻ tấn công tạo JWT không ký với sub=1, sv=0, exp tương lai, gửi Authorization: Bearer và đọc /api/v1/mobile/records/... của user bất kỳ.

**Đề xuất sửa:** Trong read_token (tokens.py) xoá verify_signature=False để mặc định kiểm tra chữ ký, giữ algorithms=[HS256], require thêm sv; thêm test token giả mạo/sai chữ ký trả 401.

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/mobile/tokens.py:17`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** JWT_SECRET được hard-code trong tokens.py:17 (Bandit và Gitleaks cùng báo). Vi phạm R-09: secret chỉ được đọc từ biến môi trường. Ai có mã nguồn đều ký được token hợp lệ.

**Kịch bản khai thác:** Kẻ tấn công đọc repo, lấy JWT_SECRET, tự ký token với sub của user bất kỳ (bác sĩ/ADMIN) rồi đọc bệnh án.

Gộp các phát hiện: `bandit:B105:app/medicare/mobile/tokens.py:17`, `gitleaks:generic-api-key:app/medicare/mobile/tokens.py:17`

**Đề xuất sửa:** Xoá secret khỏi mã nguồn; nạp từ biến môi trường qua Settings (medicare/config.py) với một secret JWT riêng, ứng dụng không khởi động nếu thiếu hoặc quá yếu. Xoay (rotate) secret đã lộ và dọn lịch sử git.

#### 🔴 TP · HIGH · python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) — `app/medicare/mobile/tokens.py:36`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** issue_token ký bằng JWT_SECRET hard-code (cùng gốc với F2), vi phạm R-09.

**Kịch bản khai thác:** Như F2: giả mạo token bằng secret lộ trong mã nguồn.

**Đề xuất sửa:** Đọc JWT secret từ biến môi trường qua Settings, không hard-code; rotate secret cũ.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Không tìm thấy middleware đặt header bảo mật nào trong code (search rỗng), nên cảnh báo ZAP có khả năng đúng, nhưng liên quan route HTML hiện có chứ không phải mã của PR. Cần xác nhận cấu hình reverse proxy.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F5: không có X-Frame-Options/CSP trong code; ngoài phạm vi PR, cần kiểm tra proxy.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong code; ngoài phạm vi PR, cần kiểm tra proxy.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP là cấu hình toàn cục, không do PR; cần xác nhận cấu hình proxy.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP là cấu hình toàn cục, không do PR.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP là cấu hình toàn cục, không do PR.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP là cấu hình toàn cục, không do PR.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP là cấu hình toàn cục, không do PR.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options là cấu hình toàn cục, ngoài PR.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** /health chỉ trả JSON tĩnh; tác động thấp, cấu hình toàn cục ngoài PR.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B105 (bandit)** — `app/medicare/mobile/router.py:55`: "token_type" là hằng số kiểu OAuth ("bearer"), không phải mật khẩu. Bandit B105 báo nhầm do tên khoá chứa "token".

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 49.3 s · 24 lần gọi LLM · 20 lần gọi công cụ · 107197 token vào / 7669 token ra · ≈ $0.1311 · chạm giới hạn: không</sub>
