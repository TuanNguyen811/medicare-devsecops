<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `f95ff81`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/appointment/sms.py:13` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/remind:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🟡 NEEDS_REVIEW | LOW | bandit | B310 (bandit) | `app/medicare/appointment/sms.py:50` | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/appointment/sms.py:13`

CWE-798 · OWASP A04 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** ESMS_API_KEY và ESMS_SECRET_KEY được hard-code trong sms.py (dòng 13-14) và được dùng ở send_sms. Bất kỳ ai đọc được repo đều dùng được tài khoản SMS brandname.

Gộp các phát hiện: `bandit:B105:app/medicare/appointment/sms.py:14`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:13`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:14`

**Đề xuất sửa:** Xoá khoá khỏi mã nguồn và thu hồi/xoay (rotate) ngay cặp khoá eSMS đã lộ, kể cả trong lịch sử git. Đọc ESMS_API_KEY và ESMS_SECRET_KEY từ biến môi trường/secret manager qua cấu hình settings của ứng dụng, và báo lỗi khi thiếu.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options/frame-ancestors; main.py chỉ có middleware lỗi, metrics và một middleware khác, không có security headers.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking; không có cấu hình header nào trong repo.

**Đề xuất sửa:** Dùng middleware security headers chung trong app/medicare/main.py đặt X-Frame-Options: DENY / frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers ở app/medicare/main.py, đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm header Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/remind:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header nosniff trong repo.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header nosniff trong repo, kể cả /health.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff qua middleware chung trong app/medicare/main.py.

#### 🟡 NEEDS_REVIEW · LOW · B310 (bandit) — `app/medicare/appointment/sms.py:50`

CWE-22 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] URL truyền vào urlopen là hằng số https (ESMS_URL), không có dữ liệu người dùng quyết định scheme, nên không thể dùng file:/ hay scheme tuỳ ý.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 35.8 s · 19 lần gọi LLM · 18 lần gọi công cụ · 69692 token vào / 5294 token ra · ≈ $0.1128 · chạm giới hạn: không</sub>
