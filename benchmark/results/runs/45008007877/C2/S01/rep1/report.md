<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `25e84cd`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | semgrep | python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text (semgrep) | `app/medicare/patient/service.py:80` | 0.98 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text (semgrep) — `app/medicare/patient/service.py:80`

CWE-89 · OWASP A05 · độ tin cậy 0.98 · nguồn: semgrep

**Phân tích:** Tham số `area` từ query string của GET /patients/search được nối trực tiếp vào `text(f"... ILIKE '%{area.strip()}%'")`, không dùng bind parameter. Server không kiểm tra, chỉ có maxlength ở HTML. User staff có thể chèn `' OR 1=1 --` hoặc UNION để vượt `_scope_filter` (R-01) và đọc dữ liệu ngoài phạm vi, kể cả bảng khác (bệnh án, R-12).

**Kịch bản khai thác:** Y tá khoa NOI gọi /patients/search?area=' OR 1=1 OR '%25'=' để bỏ qua bộ lọc khoa, hoặc dùng UNION SELECT để đọc bảng users/medical_records.

Gộp các phát hiện: `semgrep:python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text:app/medicare/patient/service.py:80`, `semgrep:security.semgrep.medicare.sqlalchemy-text-fstring:app/medicare/patient/service.py:80`

**Đề xuất sửa:** Trong service.advanced_search, bỏ text() + f-string; dùng toán tử SQLAlchemy: Patient.address.icontains(area.strip(), autoescape=True) (giống cách Patient.phone.startswith(..., autoescape=True) ở trên). Thêm test với payload chứa dấu nháy đơn.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có mã nào trong repo đặt X-Frame-Options hay CSP frame-ancestors; main.py chỉ thêm middleware lỗi, session, metrics. Ứng dụng có thể bị nhúng iframe (clickjacking). Lỗi có từ trước PR.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Như F2: không có header chống clickjacking trong toàn ứng dụng, trang /login có thể bị nhúng iframe. Lỗi có từ trước PR.

**Đề xuất sửa:** Dùng middleware chung trong app/medicare/main.py đặt X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo. Lỗi toàn cục, có từ trước PR.

**Đề xuất sửa:** Thêm header Content-Security-Policy (default-src 'self', frame-ancestors 'none') bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo. Lỗi toàn cục, có từ trước PR.

**Đề xuất sửa:** Thêm header Content-Security-Policy bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo. Lỗi toàn cục, có từ trước PR.

**Đề xuất sửa:** Thêm header Content-Security-Policy bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo. Lỗi toàn cục, có từ trước PR.

**Đề xuất sửa:** Thêm header Content-Security-Policy bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo. Lỗi toàn cục, có từ trước PR.

**Đề xuất sửa:** Thêm header Content-Security-Policy bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng; không có mã nào đặt header này.

**Đề xuất sửa:** Middleware chung trong app/medicare/main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân là không có middleware security headers.

**Đề xuất sửa:** Middleware chung trong app/medicare/main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có mã nào đặt X-Content-Type-Options trong repo. Lỗi cấu hình toàn cục, có từ trước PR, rủi ro thấp.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung trong app/medicare/main.py đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 56.8 s · 27 lần gọi LLM · 15 lần gọi công cụ · 122868 token vào / 9138 token ra · ≈ $0.1971 · chạm giới hạn: không</sub>
