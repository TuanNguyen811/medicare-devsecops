<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `6d5288d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | export_record thiếu kiểm tra policy.can_view_record (IDOR bệnh án) | `app/medicare/record/export.py:40` | 0.95 |
| 🔴 TP | HIGH | agent | Path traversal qua tham số letterhead trong export_record | `app/medicare/record/export.py:28` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.85 |

### Chi tiết

#### 🔴 TP · CRITICAL · export_record thiếu kiểm tra policy.can_view_record (IDOR bệnh án) — `app/medicare/record/export.py:40`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** get_record_for_export chỉ db.get rồi ghi audit, không gọi policy.can_view_record. Mọi DOCTOR/NURSE/PATIENT đều xuất được bệnh án của bất kỳ bệnh nhân nào (vi phạm R-01, R-02, R-03 và R-15 vì không tồn tại/không có quyền phải cùng 404). Nên dùng service.get_record_for đã có sẵn kiểm tra.

**Kịch bản khai thác:** Bệnh nhân A duyệt record_id tuần tự qua /records/{id}/export và tải chẩn đoán, ghi chú của bệnh nhân khác.

**Đề xuất sửa:** Trong get_record_for_export, nạp bệnh nhân và gọi policy.can_view_record(user, patient) (hoặc tái sử dụng record.service.get_record_for); nếu không có quyền thì raise NotFound giống như không tồn tại, và chỉ ghi audit sau khi qua kiểm tra. Thêm test bệnh nhân/bác sĩ khác khoa nhận 404.

#### 🔴 TP · HIGH · Path traversal qua tham số letterhead trong export_record — `app/medicare/record/export.py:28`

CWE-22 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Tham số query `letterhead` đi thẳng vào `LETTERHEAD_DIR / name` mà không đối chiếu allowlist. Có thể dùng `../../...` hoặc đường dẫn tuyệt đối (pathlib bỏ qua thư mục gốc) để đọc file tùy ý, nội dung được in vào phiếu khám trả về cho người dùng.

**Kịch bản khai thác:** Bệnh nhân gọi GET /records/{id}/export?format=txt&letterhead=/etc/passwd (hoặc ../../../.env) và nhận nội dung file của server, kể cả secret.

**Đề xuất sửa:** Trong export.read_letterhead, chỉ chấp nhận `name` nằm trong tập `letterheads()` (allowlist tên file); nếu không thuộc thì dùng DEFAULT_LETTERHEAD hoặc trả 400. Không ghép trực tiếp chuỗi người dùng vào đường dẫn.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** create_app không có middleware nào đặt header bảo mật; tìm toàn repo không thấy X-Frame-Options hay frame-ancestors.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Trang /login cũng không có header chống clickjacking; không có middleware đặt header.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong create_app (X-Frame-Options: DENY, CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options/CSP trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung trong create_app đặt X-Content-Type-Options: nosniff và Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff; không middleware nào đặt.

**Đề xuất sửa:** Middleware chung trong create_app đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff; không middleware nào đặt.

**Đề xuất sửa:** Middleware chung trong create_app đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 42.7 s · 20 lần gọi LLM · 19 lần gọi công cụ · 142642 token vào / 6111 token ra · ≈ $0.1592 · chạm giới hạn: không</sub>
