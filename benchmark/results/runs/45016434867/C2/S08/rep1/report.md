<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `f95ff81`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/appointment/sms.py:13` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/remind:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🟡 NEEDS_REVIEW | LOW | bandit | B310 (bandit) | `app/medicare/appointment/sms.py:50` | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/appointment/sms.py:13`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** Hai dòng 13-14 trong sms.py gán cứng ESMS_API_KEY và ESMS_SECRET_KEY (được dùng trong send_sms). Vi phạm R-09: secret chỉ đọc từ biến môi trường.

Gộp các phát hiện: `bandit:B105:app/medicare/appointment/sms.py:14`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:13`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:14`

**Đề xuất sửa:** Thu hồi/xoay khóa eSMS đã lộ. Trong sms.py đọc ESMS_API_KEY và ESMS_SECRET_KEY từ biến môi trường (qua settings của app), báo lỗi khi thiếu. Xóa khỏi lịch sử git.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header X-Frame-Options hay CSP frame-ancestors ở đâu trong mã; main.py chỉ có middleware lỗi, session và metrics.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F3: thiếu header chống clickjacking toàn app, kể cả /login.

**Đề xuất sửa:** Dùng chung middleware security headers (X-Frame-Options DENY, CSP frame-ancestors) trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options trong mã.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers ở main.py, đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong mã.

**Đề xuất sửa:** Thêm header Content-Security-Policy chặt (default-src 'self') qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong mã.

**Đề xuất sửa:** Dùng middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/remind:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong mã, áp dụng cả cho route remind mới.

**Đề xuất sửa:** Dùng middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong mã.

**Đề xuất sửa:** Dùng middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong mã.

**Đề xuất sửa:** Dùng middleware CSP chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options toàn app.

**Đề xuất sửa:** Thêm nosniff qua middleware security headers dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options toàn app, gồm /health.

**Đề xuất sửa:** Thêm nosniff qua middleware security headers dùng chung.

#### 🟡 NEEDS_REVIEW · LOW · B310 (bandit) — `app/medicare/appointment/sms.py:50`

CWE-22 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] URL của urlopen là hằng số https ESMS_URL, không có đầu vào người dùng, nên không thể dùng scheme file:/ tùy ý.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 55.5 s · 30 lần gọi LLM · 18 lần gọi công cụ · 122481 token vào / 9770 token ra · ≈ $0.2039 · chạm giới hạn: không</sub>
