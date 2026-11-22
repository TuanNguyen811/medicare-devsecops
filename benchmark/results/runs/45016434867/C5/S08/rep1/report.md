<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `f95ff81`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/appointment/sms.py:13` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/remind:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🟡 NEEDS_REVIEW | LOW | bandit | B310 (bandit) | `app/medicare/appointment/sms.py:50` | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/appointment/sms.py:13`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** sms.py dòng 13-14 gán cứng ESMS_API_KEY và ESMS_SECRET_KEY (Gitleaks và Bandit cùng báo). Vi phạm R-09: secret chỉ được đọc từ biến môi trường.

Gộp các phát hiện: `bandit:B105:app/medicare/appointment/sms.py:14`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:13`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:14`

**Đề xuất sửa:** Xóa giá trị khỏi mã nguồn và thu hồi/xoay (rotate) cặp khóa eSMS đã lộ, kể cả trong lịch sử git. Đọc ESMS_API_KEY và ESMS_SECRET_KEY từ biến môi trường qua config của ứng dụng (như SECRET_KEY), báo lỗi rõ ràng khi thiếu.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không tìm thấy code nào đặt X-Frame-Options hoặc frame-ancestors; main.py chỉ có Session, CatchAll và Metrics middleware.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F3: không có header chống clickjacking, /login có thể bị nhúng iframe.

**Đề xuất sửa:** Đặt X-Frame-Options: DENY / CSP frame-ancestors 'none' bằng middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Mã nguồn không đặt X-Content-Type-Options: nosniff ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong mã.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware security headers ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong mã, cùng nguyên nhân với F8.

**Đề xuất sửa:** Thêm CSP bằng middleware chung ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/remind:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong mã, cùng nguyên nhân với F8.

**Đề xuất sửa:** Thêm CSP bằng middleware chung ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong mã, cùng nguyên nhân với F8.

**Đề xuất sửa:** Thêm CSP bằng middleware chung ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong mã, cùng nguyên nhân với F8.

**Đề xuất sửa:** Thêm CSP bằng middleware chung ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, cùng nguyên nhân với F7.

**Đề xuất sửa:** Dùng middleware security headers chung, đặt nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, cùng nguyên nhân với F7.

**Đề xuất sửa:** Dùng middleware security headers chung, đặt nosniff.

#### 🟡 NEEDS_REVIEW · LOW · B310 (bandit) — `app/medicare/appointment/sms.py:50`

CWE-22 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] URL của urlopen là hằng số https (ESMS_URL), không do người dùng điều khiển nên không thể dùng scheme file:/ tùy ý.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 58.7 s · 30 lần gọi LLM · 18 lần gọi công cụ · 123245 token vào / 8760 token ra · ≈ $0.1939 · chạm giới hạn: không</sub>
