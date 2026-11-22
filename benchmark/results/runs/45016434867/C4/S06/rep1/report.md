<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `b6844e9`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/detail.html:29` | 0.97 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.85 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/detail.html:29`

CWE-79 · OWASP A05 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** note.body là HTML do người dùng gửi lên, server chỉ strip và kiểm tra độ dài, không làm sạch. Template render bằng |safe nên đây là stored XSS. Bác sĩ khác, hoặc bệnh nhân xem phiếu khám, đều chạy script của kẻ tấn công. Cũng không có CSP để giảm thiểu.

**Kịch bản khai thác:** Kẻ tấn công POST trực tiếp body=<img src=x onerror=...> (không cần editor JS). Script chạy trong phiên của bệnh nhân hoặc bác sĩ khi họ mở phiếu khám và có thể đánh cắp dữ liệu hoặc thực hiện thao tác thay họ.

**Đề xuất sửa:** Trong service.add_note, làm sạch HTML bằng allowlist phía server (ví dụ thư viện nh3 hoặc bleach, chỉ cho phép p, b, i, u, ul, li, br và không cho attribute). Có thể làm sạch lần nữa khi render, hoặc bỏ |safe trong detail.html và dùng filter đã sanitize. Thêm test với payload <script> và onerror.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** create_app trong main.py không có middleware đặt header bảo mật, và không tìm thấy X-Frame-Options hay CSP ở bất kỳ đâu trong repo.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo (xem main.py, create_app).

**Đề xuất sửa:** Dùng middleware chung trong main.py đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware trong main.py thêm X-Content-Type-Options: nosniff cho mọi response, kể cả /static.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo. Điều này càng quan trọng vì PR render HTML bằng |safe.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', không cho inline script) qua middleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

**Đề xuất sửa:** Dùng cùng middleware security headers trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo, kể cả với /health.

**Đề xuất sửa:** Dùng cùng middleware security headers trong main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 30.9 s · 16 lần gọi LLM · 15 lần gọi công cụ · 73501 token vào / 4531 token ra · ≈ $0.1067 · chạm giới hạn: không</sub>
