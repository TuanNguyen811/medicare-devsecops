<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 13 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 3 phát hiện mới do Agent tự tìm · commit `6d5288d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Path traversal qua tham số letterhead | `app/medicare/record/export.py:27` | 0.90 |
| 🔴 TP | HIGH | agent | IDOR: export_record không kiểm tra policy.can_view_record | `app/medicare/record/export.py:40` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | agent | Xuất HTML có thể bị chèn header/CSP; filename dùng dữ liệu nội bộ - phiếu HTML thiếu kiểm soát | `app/medicare/record/router.py:139` | 0.30 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Path traversal qua tham số letterhead — `app/medicare/record/export.py:27`

CWE-22 · OWASP A01 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Tham số query letterhead do người dùng kiểm soát được nối trực tiếp vào LETTERHEAD_DIR / name mà không kiểm tra whitelist. Dùng "../../.." hoặc đường dẫn tuyệt đối (pathlib bỏ qua thư mục gốc) để đọc file văn bản bất kỳ (ví dụ .env, /etc/passwd); nội dung được in ra trong phản hồi. Chỉ FileNotFoundError được bắt.

**Kịch bản khai thác:** Gọi GET /records/1/export?format=txt&letterhead=../../../../.env để nhận secret của ứng dụng trong phần đầu phiếu.

**Đề xuất sửa:** Trong export.read_letterhead, chỉ chấp nhận tên có trong tập letterheads() (whitelist); nếu không thì dùng DEFAULT_LETTERHEAD. Ngoài ra resolve đường dẫn và kiểm tra nó nằm trong LETTERHEAD_DIR. Xử lý cả các lỗi OSError/UnicodeDecodeError.

#### 🔴 TP · HIGH · IDOR: export_record không kiểm tra policy.can_view_record — `app/medicare/record/export.py:40`

CWE-639 · OWASP A01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** get_record_for_export dùng db.get(MedicalRecord, record_id) rồi trả về bệnh án mà không gọi policy.can_view_record (khác với service.get_record_for). Mọi DOCTOR/NURSE/PATIENT đăng nhập đều xuất được bệnh án của bất kỳ bệnh nhân nào (khác khoa, bệnh nhân khác). Đồng thời ghi audit EXPORT_RECORD trước khi kiểm tra quyền.

**Kịch bản khai thác:** Bệnh nhân A đăng nhập và gọi GET /records/<id người khác>/export?format=txt, lặp id tuần tự để tải toàn bộ bệnh án của bệnh nhân khác.

**Đề xuất sửa:** Trong export.get_record_for_export, tải bệnh án qua service.get_record_for (hoặc _load) rồi gọi policy.can_view_record(user, patient); nếu không được phép thì metrics.authz_denied và raise NotFound như record_detail. Chỉ ghi audit sau khi qua kiểm tra quyền. Thêm test: bệnh nhân/bác sĩ khác khoa nhận 404.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app chỉ thêm CatchAllErrors, Session, Metrics middleware; không có middleware đặt X-Frame-Options / frame-ancestors, nên thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Frame-Options trong create_app; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware security headers chung trong app/medicare/main.py đặt X-Frame-Options: DENY / frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có mã nào trong repo đặt X-Content-Type-Options; thiếu nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware security headers trong main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy được đặt ở bất kỳ đâu trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self') trong middleware security headers ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng; cùng nguyên nhân gốc.

**Đề xuất sửa:** Middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng; cùng nguyên nhân gốc.

**Đề xuất sửa:** Middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng; cùng nguyên nhân gốc.

**Đề xuất sửa:** Middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng; cùng nguyên nhân gốc.

**Đề xuất sửa:** Middleware CSP chung trong main.py.

#### 🔴 TP · LOW · Xuất HTML có thể bị chèn header/CSP; filename dùng dữ liệu nội bộ - phiếu HTML thiếu kiểm soát — `app/medicare/record/router.py:139`

CWE-79 · OWASP A05 · độ tin cậy 0.30 · nguồn: agent

**Phân tích:** Template print.html render qua templates.get_template; cần xác nhận autoescape bật cho .html. Nếu tắt thì symptoms/notes gây XSS. Mức tin cậy thấp.

**Đề xuất sửa:** Xác nhận Jinja2 autoescape bật cho templates; thêm header X-Content-Type-Options: nosniff và CSP cho phản hồi export.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options do không có middleware đặt header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân gốc.

**Đề xuất sửa:** Middleware security headers chung trong main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 43.7 s · 20 lần gọi LLM · 19 lần gọi công cụ · 97771 token vào / 6543 token ra · ≈ $0.1404 · chạm giới hạn: không</sub>
