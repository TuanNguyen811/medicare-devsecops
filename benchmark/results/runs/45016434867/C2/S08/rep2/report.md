<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `f95ff81`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/appointment/sms.py:13` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/remind:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🟡 NEEDS_REVIEW | LOW | bandit | B310 (bandit) | `app/medicare/appointment/sms.py:50` | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/appointment/sms.py:13`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** sms.py dòng 13-14 gán ESMS_API_KEY và ESMS_SECRET_KEY là hằng số trong mã nguồn (Gitleaks và Bandit cùng báo). Vi phạm R-09: secret chỉ được đọc từ biến môi trường.

**Kịch bản khai thác:** Ai đọc được repo đều lấy được key eSMS và có thể gửi SMS giả danh brandname MEDICARE, gây tốn tiền tài khoản.

Gộp các phát hiện: `bandit:B105:app/medicare/appointment/sms.py:14`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:13`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:14`

**Đề xuất sửa:** Thu hồi (rotate) key eSMS đã lộ và xóa khỏi lịch sử git. Trong sms.py, đọc ESMS_API_KEY và ESMS_SECRET_KEY từ biến môi trường qua cơ chế cấu hình của app (như SECRET_KEY, R-09). Báo lỗi rõ ràng khi thiếu.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong code không thấy chỗ nào đặt X-Frame-Options hay frame-ancestors, nên ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware đặt header bảo mật cho mọi response: X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Frame-Options hay frame-ancestors trong code, nên trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong code.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong code.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/remind:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong code.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong code.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong code.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng, không có code nào đặt header này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options cho /health, cùng nguyên nhân là chưa có middleware header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options, nên header này thiếu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm vào middleware header bảo mật chung: X-Content-Type-Options: nosniff.

#### 🟡 NEEDS_REVIEW · LOW · B310 (bandit) — `app/medicare/appointment/sms.py:50`

CWE-22 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] URL của urlopen là hằng số ESMS_URL dùng https, không chứa dữ liệu người dùng, nên không thể dùng scheme file:/ hay URL tùy ý. Chỉ phone và nội dung nằm trong body JSON.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 43.9 s · 17 lần gọi LLM · 16 lần gọi công cụ · 48819 token vào / 5463 token ra · ≈ $0.0846 · chạm giới hạn: không</sub>
