<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `6d5288d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Path traversal qua tham số letterhead trong read_letterhead | `app/medicare/record/export.py:28` | 0.90 |
| 🔴 TP | HIGH | agent | IDOR: export bệnh án không kiểm tra policy.can_view_record | `app/medicare/record/export.py:38` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Path traversal qua tham số letterhead trong read_letterhead — `app/medicare/record/export.py:28`

CWE-22 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Tham số query letterhead do người dùng kiểm soát được nối trực tiếp vào LETTERHEAD_DIR / name mà không đối chiếu allowlist (letterheads()). Giá trị như ../../../../etc/passwd hoặc đường dẫn tuyệt đối (pathlib bỏ qua thư mục gốc) sẽ được đọc và chèn vào nội dung file tải xuống. Vi phạm R-14.

**Kịch bản khai thác:** GET /records/1/export?format=txt&letterhead=../../../../etc/passwd hoặc ../../.env: nội dung file (SECRET_KEY, DATABASE_URL) được in ở đầu file txt trả về.

**Đề xuất sửa:** Trong export.read_letterhead, chỉ chấp nhận name nằm trong allowlist letterheads(); nếu không thì dùng DEFAULT_LETTERHEAD (hoặc trả 400). Không ghép trực tiếp giá trị từ client vào đường dẫn; có thể ánh xạ khóa -> Path đã biết.

#### 🔴 TP · HIGH · IDOR: export bệnh án không kiểm tra policy.can_view_record — `app/medicare/record/export.py:38`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** get_record_for_export chỉ db.get rồi ghi audit, không gọi policy.can_view_record. Bất kỳ DOCTOR/NURSE/PATIENT nào đăng nhập đều xuất được bệnh án của bệnh nhân khác (khác khoa, không phụ trách, không phải của mình), vi phạm R-01, R-02, R-12. Ngoài ra bản ghi tồn tại nhưng không có quyền cũng không trả 404 (R-15).

**Kịch bản khai thác:** Bệnh nhân A đăng nhập, duyệt /records/{id}/export với id tuần tự của bệnh nhân B và tải về chẩn đoán, triệu chứng, ghi chú của B.

**Đề xuất sửa:** Trong export.get_record_for_export (hoặc dùng lại service.get_record_for/_load), tải bệnh nhân rồi gọi policy.can_view_record(user, patient); nếu không có quyền thì ghi metrics.authz_denied và raise NotFound giống như bản ghi không tồn tại (R-15). Chỉ ghi audit EXPORT_RECORD sau khi qua kiểm tra quyền. Bổ sung test: bệnh nhân khác, bác sĩ/y tá khác khoa nhận 404.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app chỉ thêm middleware lỗi, session và metrics; không có middleware đặt X-Frame-Options hay CSP frame-ancestors nên mọi response đều thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm một middleware trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking vì không có middleware security headers nào trong create_app.

**Đề xuất sửa:** Dùng chung middleware security headers trong app/medicare/main.py: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu; thiếu lớp phòng thủ chiều sâu chống XSS.

**Đề xuất sửa:** Thêm CSP (default-src 'self', frame-ancestors 'none') qua middleware security headers trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware security headers trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware security headers trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware security headers trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware security headers trong create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu nosniff toàn cục, không có middleware đặt header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu nosniff toàn cục, kể cả /health; một middleware sẽ sửa được tất cả.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff. Đặc biệt export mới trả file attachment có nội dung do người dùng nhập, nên cần nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers trong create_app thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 56.9 s · 18 lần gọi LLM · 17 lần gọi công cụ · 138804 token vào / 7196 token ra · ≈ $0.1218 · chạm giới hạn: không</sub>
