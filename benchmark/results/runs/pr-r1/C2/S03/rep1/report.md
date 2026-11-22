<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 3 lỗi cần sửa

🟢 1 báo nhầm của công cụ quét đã được gỡ · 📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `00ff7d9`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) | `app/medicare/mobile/tokens.py:43` | semgrep | 0.97 |
| 🔴 TP | HIGH | generic-api-key (gitleaks) | `app/medicare/mobile/tokens.py:17` | gitleaks | 0.90 |
| 🔴 TP | HIGH | python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) | `app/medicare/mobile/tokens.py:36` | semgrep | 0.90 |

### Chi tiết

#### 🔴 TP · CRITICAL · python.jwt.security.unverified-jwt-decode.unverified-jwt-decode (semgrep) — `app/medicare/mobile/tokens.py:43`

CWE-347 · OWASP A07 · vi phạm R-01 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** read_token giải mã với "verify_signature": False nên chữ ký không được kiểm tra. Kẻ tấn công không cần biết secret, chỉ cần tạo JWT tùy ý (sub = id nạn nhân, sv = session_version đoán được, exp tương lai) là xác thực thành công: bypass xác thực hoàn toàn, truy cập bệnh án (R-01, R-02).

**Kịch bản khai thác:** Kẻ tấn công tạo token không chữ ký/chữ ký sai với sub=1, sv=0, exp xa, gửi Authorization: Bearer ... và đọc dữ liệu của bất kỳ user nào, kể cả bác sĩ/admin.

**Đề xuất sửa:** Trong read_token (tokens.py) bỏ "verify_signature": False; để PyJWT xác thực chữ ký với khóa từ env và algorithms=["HS256"], giữ verify_exp và require. Thêm test token giả mạo/sai chữ ký trả 401.

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/mobile/tokens.py:17`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** JWT_SECRET bị hard-code trong tokens.py:17 (Gitleaks bắt), vi phạm R-09: secret chỉ đọc từ biến môi trường. Ai đọc được mã nguồn đều có thể ký token hợp lệ cho bất kỳ user nào.

**Kịch bản khai thác:** Kẻ tấn công có mã nguồn/repo tự ký JWT với sub=ID của admin/bác sĩ và sv tương ứng, rồi đọc bệnh án qua /api/v1/mobile.

Gộp các phát hiện: `bandit:B105:app/medicare/mobile/tokens.py:17`, `gitleaks:generic-api-key:app/medicare/mobile/tokens.py:17`

**Đề xuất sửa:** Xóa secret khỏi tokens.py; đọc khóa JWT từ biến môi trường qua Settings trong medicare/config.py (riêng khỏi SECRET_KEY, ít nhất 256 bit), ứng dụng không khởi động nếu thiếu. Xoay (rotate) secret đã lộ trong git history.

#### 🔴 TP · HIGH · python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret (semgrep) — `app/medicare/mobile/tokens.py:36`

CWE-522 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: semgrep

**Phân tích:** jwt.encode dùng JWT_SECRET hard-code (cùng gốc với F2), vi phạm R-09.

**Kịch bản khai thác:** Có secret trong mã nguồn thì có thể giả mạo token cho mọi tài khoản.

**Đề xuất sửa:** Nạp JWT_SECRET từ biến môi trường qua Settings, không hard-code; dùng trong issue_token và read_token.

<details><summary>🟢 Báo nhầm của công cụ quét đã gỡ: 1</summary>

- **B105 (bandit)** — `app/medicare/mobile/router.py:55`: "token_type" là hằng OAuth ("bearer"), không phải mật khẩu; Bandit nhầm theo tên khóa. Giá trị access_token được sinh động bởi issue_token.

</details>

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Không tìm thấy X-Frame-Options/CSP frame-ancestors ở đâu trong mã (search_code rỗng); lỗi cấu hình toàn ứng dụng, có sẵn từ trước PR. | Thêm middleware security headers trong create_app (main.py): X-Frame-Options: DENY, CSP frame-ancestors 'none', X-Content-Type-Options: nosniff. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Thiếu CSP toàn ứng dụng; không có mã nào đặt Content-Security-Policy. | Thêm CSP chặt (default-src 'self') qua middleware chung trong main.py. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options toàn ứng dụng. | Middleware chung đặt X-Content-Type-Options: nosniff trong main.py. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Thiếu X-Content-Type-Options trên toàn ứng dụng; không có middleware đặt header. | Middleware chung trong main.py đặt X-Content-Type-Options: nosniff. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 43.8 s · 20 lần gọi LLM · 19 lần gọi công cụ · 125431 token vào / 6462 token ra · ≈ $0.1603 · chạm giới hạn: không</sub>
