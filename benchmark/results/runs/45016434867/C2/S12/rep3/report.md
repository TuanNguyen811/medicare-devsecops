<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `d3be9b5`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Ghi PII (CCCD, mã BHYT, chẩn đoán) vào log | `app/medicare/record/service.py:23` | 0.95 |
| 🔴 TP | MEDIUM | agent | Job bảo trì xóa dòng audit log (audit log không còn bất biến) | `app/medicare/audit/maintenance.py:40` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Ghi PII (CCCD, mã BHYT, chẩn đoán) vào log — `app/medicare/record/service.py:23`

CWE-532 · OWASP A09 · vi phạm R-10 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** _log_event ghi national_id, insurance_number và diagnosis vào log JSON (JsonFormatter đưa mọi trường extra lên top-level, gửi tới Loki). Vi phạm R-10; đồng thời bỏ qua việc che dữ liệu của R-11 vì log ghi giá trị đầy đủ, ai đọc log cũng thấy, kể cả bác sĩ/y tá vốn chỉ được xem bản bị che.

**Kịch bản khai thác:** Người có quyền đọc log (vận hành, Loki) lấy được CCCD, mã BHYT và chẩn đoán đầy đủ của bệnh nhân mỗi lần hồ sơ được xem hoặc sửa.

**Đề xuất sửa:** Trong app/medicare/record/service.py, hàm _log_event: bỏ national_id, insurance_number và diagnosis khỏi extra. Chỉ giữ định danh không nhạy cảm (user_id, role, record_id, patient_code). Nếu cần thêm thông tin, tra cứu qua audit log hoặc bản đã che.

#### 🔴 TP · MEDIUM · Job bảo trì xóa dòng audit log (audit log không còn bất biến) — `app/medicare/audit/maintenance.py:40`

CWE-779 · OWASP A09 · vi phạm R-06 · độ tin cậy 0.85 · nguồn: agent

**Phân tích:** compact_repeated_views thực hiện DELETE trên bảng AuditLog. R-06 quy định audit log chỉ được thêm, không có chức năng xóa. R-05 yêu cầu ghi mọi lần truy cập bệnh án, nên việc xóa các lần xem lặp làm mất bằng chứng truy cập. Chỉ bản ghi đầu của mỗi đợt còn lại, nên không thể tái dựng đầy đủ các lần xem.

**Kịch bản khai thác:** Người dùng nội bộ xem hồ sơ lặp lại nhiều lần; job xóa các lần xem sau, nên điều tra sự cố không xác định được phạm vi truy cập thật.

**Đề xuất sửa:** Bỏ thao tác DELETE trên AuditLog trong compact_repeated_views (app/medicare/audit/maintenance.py). Giảm tải ở phía ghi, ví dụ dedupe khi gọi audit.log_access, hoặc dùng partition và archive bất biến. Nếu bắt buộc giữ lại, cần ADMIN phê duyệt thay đổi R-06 và ghi lại việc nén.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options hay frame-ancestors, nên ứng dụng không đặt header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py (create_app): X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo, trang /login có thể bị nhúng vào iframe.

**Đề xuất sửa:** Thêm middleware security headers trong create_app (app/medicare/main.py): X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') qua middleware chung trong create_app, áp dụng cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung trong create_app, áp dụng cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung trong create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu, kể cả /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong create_app, áp dụng cho cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung trong create_app (app/medicare/main.py).

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 40.2 s · 17 lần gọi LLM · 16 lần gọi công cụ · 86038 token vào / 5297 token ra · ≈ $0.0884 · chạm giới hạn: không</sub>
