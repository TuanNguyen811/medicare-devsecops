<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `c4b6f8b`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | SSTI: render mẫu Jinja do bác sĩ nhập bằng Environment không sandbox | `app/medicare/record/printing.py:97` | 0.90 |
| 🔴 TP | HIGH | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/record/slip.html:17` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · SSTI: render mẫu Jinja do bác sĩ nhập bằng Environment không sandbox — `app/medicare/record/printing.py:97`

CWE-1336 · OWASP A05 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** printing.py dùng jinja2.Environment thường (không SandboxedEnvironment) và from_string(body).render() trên body do bác sĩ gửi lên. validate() chỉ parse cú pháp. Bác sĩ có thể dùng {{ record.__class__.__init__.__globals__ ... }} hoặc cycler/lipsum để truy cập os và thực thi mã tùy ý trên server, đọc SECRET_KEY, DB toàn bộ PII. Ngoài ra slip.html dùng |safe nên HTML/JS của bác sĩ chạy trong origin ứng dụng khi bệnh nhân/bác sĩ khác mở phiếu (với người dùng được xem). Ghi chú: slip chỉ dùng template của người xem, nhưng XSS/SSTI vẫn là tự gây ra + RCE.

**Kịch bản khai thác:** Bác sĩ (hoặc tài khoản bác sĩ bị chiếm) lưu mẫu chứa {{ cycler.__init__.__globals__.os.popen('id').read() }}, mở /records/{id}/print và thực thi lệnh trên server.

**Đề xuất sửa:** Trong app/medicare/record/printing.py thay Environment bằng jinja2.sandbox.SandboxedEnvironment (autoescape=True) cho cả validate() và render_slip(); chỉ cho truyền dict giá trị thuần; hạn chế tag/filter. Tốt hơn: bỏ cho phép HTML thô, chỉ cho chọn bố cục có sẵn hoặc thay biến bằng chuỗi placeholder tự thay thế. Đồng thời xử lý ngoại lệ khi render để không lộ lỗi.

#### 🔴 TP · HIGH · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/record/slip.html:17`

CWE-79 · OWASP A05 · độ tin cậy 0.85 · nguồn: semgrep

**Phân tích:** slip.html in {{ slip | safe }} với slip được render từ mẫu HTML do bác sĩ tự viết, nên không có escape; mẫu có thể chứa <script>. Phiếu được bệnh nhân và bác sĩ khác xem được (qua can_* của record), nhưng mẫu dùng là của người xem; vẫn là sink nguy hiểm kết hợp SSTI và nội dung do người dùng kiểm soát.

**Đề xuất sửa:** Không dùng |safe cho dữ liệu người dùng. Chỉ để HTML do hệ thống kiểm soát; làm sạch mẫu bằng bộ lọc allowlist (ví dụ bleach/nh3) sau khi render, hoặc thêm CSP nghiêm ngặt cho trang slip và dùng SandboxedEnvironment trong printing.py.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không có X-Frame-Options/CSP/nosniff nào, nên ứng dụng thiếu header bảo mật.

**Đề xuất sửa:** Thêm middleware toàn cục trong app chính đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong repo.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY / frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt (default-src 'self').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 45.3 s · 15 lần gọi LLM · 14 lần gọi công cụ · 104397 token vào / 5509 token ra · ≈ $0.0905 · chạm giới hạn: không</sub>
