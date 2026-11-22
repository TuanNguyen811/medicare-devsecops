<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `d3be9b5`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Job maintenance xóa audit log, vi phạm tính bất biến | `app/medicare/audit/maintenance.py:41` | 0.90 |
| 🔴 TP | HIGH | agent | Ghi PII (CCCD, BHYT, chẩn đoán) vào log trong _log_event | `app/medicare/record/service.py:21` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Job maintenance xóa audit log, vi phạm tính bất biến — `app/medicare/audit/maintenance.py:41`

CWE-778 · OWASP A09 · vi phạm R-06 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** compact_repeated_views thực hiện delete(AuditLog) trên các dòng VIEW_RECORD. R-06 quy định audit log chỉ được thêm, không có chức năng sửa/xóa; R-05 yêu cầu ghi mọi lần truy cập bệnh án. Xóa các lần xem lặp làm mất dấu vết truy cập (thời điểm, IP) và có thể bị lợi dụng để che giấu việc truy cập trái phép.

**Kịch bản khai thác:** Kẻ truy cập trái phép xem hồ sơ nhiều lần trong 30 phút; chỉ lần đầu còn lại, các lần sau bị xóa khỏi audit, mất bằng chứng điều tra.

**Đề xuất sửa:** Bỏ job xóa audit. Nếu cần giảm lượng ghi, gộp ở thời điểm ghi trong audit.log_access (ví dụ thêm bộ đếm/last_seen) thay vì DELETE. Nếu cần lưu trữ, chuyển sang bảng archive chỉ-thêm, không xóa dữ liệu gốc, và cần phê duyệt R-06.

#### 🔴 TP · HIGH · Ghi PII (CCCD, BHYT, chẩn đoán) vào log trong _log_event — `app/medicare/record/service.py:21`

CWE-532 · OWASP A09 · vi phạm R-10 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** _log_event đưa national_id, insurance_number và diagnosis vào extra; JsonFormatter đẩy mọi trường extra lên top-level và ghi ra stderr cho log agent (Loki). Vi phạm R-10 (không ghi PII vào log) và R-11 (không che CCCD/BHYT). Log còn ghi dữ liệu mà bác sĩ/y tá không được xem đầy đủ.

**Kịch bản khai thác:** Bất kỳ ai có quyền đọc Loki/log cluster đều lấy được CCCD, mã BHYT và chẩn đoán của bệnh nhân sau mỗi lần xem/sửa bệnh án.

**Đề xuất sửa:** Trong record/service.py::_log_event, bỏ national_id, insurance_number và diagnosis khỏi extra; chỉ giữ user_id, role, record_id và patient_code (hoặc patient id). Nếu cần, thêm bộ lọc trong JsonFormatter để loại các khóa PII.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options hay frame-ancestors ở đâu, nên ứng dụng thật sự thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm một middleware security headers trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng chung middleware security headers trong main.py::create_app: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware security headers ở main.py::create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở main.py::create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở main.py::create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở main.py::create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt header nosniff.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở main.py::create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt header nosniff; /health cũng thiếu header này.

**Đề xuất sửa:** Middleware security headers áp dụng cho mọi response, gồm /health: X-Content-Type-Options nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options: nosniff ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở main.py::create_app.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 45.1 s · 15 lần gọi LLM · 14 lần gọi công cụ · 68646 token vào / 5420 token ra · ≈ $0.0849 · chạm giới hạn: không</sub>
