<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `d3be9b5`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Job compact_repeated_views xóa dòng audit log (audit không bất biến) | `app/medicare/audit/maintenance.py:41` | 0.90 |
| 🔴 TP | HIGH | agent | Ghi PII (CCCD, BHYT, chẩn đoán) vào log trong record/service._log_event | `app/medicare/record/service.py:22` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Job compact_repeated_views xóa dòng audit log (audit không bất biến) — `app/medicare/audit/maintenance.py:41`

CWE-778 · OWASP A09 · vi phạm R-06 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** maintenance.py thực hiện delete(AuditLog) các dòng VIEW_RECORD lặp trong cửa sổ 30 phút. R-06 yêu cầu audit log chỉ thêm, không xóa; R-05 yêu cầu ghi mọi lần xem bệnh án. Việc xóa làm mất dấu vết các lần truy cập (thời điểm, IP) và có thể che giấu truy cập trái phép; tham số --window-minutes tùy ý cho phép xóa rộng hơn.

**Kịch bản khai thác:** Người có quyền chạy CronJob (hoặc kẻ chiếm được nó) chạy với --window-minutes lớn để xóa gần hết dấu vết VIEW_RECORD, che giấu việc xem trộm bệnh án.

**Đề xuất sửa:** Bỏ việc xóa audit log trong audit/maintenance.py::compact_repeated_views. Nếu cần giảm dung lượng, chuyển sang giảm ghi trùng ở audit.log_access hoặc lưu trữ/partition bảng, và thu hồi quyền DELETE của DB role trên bảng audit_log.

#### 🔴 TP · HIGH · Ghi PII (CCCD, BHYT, chẩn đoán) vào log trong record/service._log_event — `app/medicare/record/service.py:22`

CWE-532 · OWASP A09 · vi phạm R-10 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** _log_event đưa national_id, insurance_number và diagnosis vào extra=; JsonFormatter đẩy mọi extra thành key JSON ra stderr rồi gửi lên Loki. Vi phạm R-10 (không ghi PII vào log) và còn bỏ qua việc che CCCD/BHYT theo R-11, vai trò log không bị giới hạn.

**Kịch bản khai thác:** Mỗi lần bác sĩ/y tá xem hoặc sửa bệnh án, CCCD, mã BHYT và chẩn đoán dạng rõ được ghi vào log tập trung; bất kỳ ai có quyền đọc Loki (không phải ADMIN/bác sĩ phụ trách) đều đọc được dữ liệu y tế nhạy cảm.

**Đề xuất sửa:** Trong record/service.py::_log_event chỉ ghi định danh không nhạy cảm (user_id, role, record_id, patient_id/patient_code); bỏ national_id, insurance_number, diagnosis. Cân nhắc thêm danh sách cho phép trường trong JsonFormatter (common/logs.py).

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app chỉ thêm middleware CatchAllErrors, Session, Metrics; không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors (search_code không thấy). Trang HTML có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py (create_app): X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking vì app không có middleware đặt header bảo mật.

**Đề xuất sửa:** Dùng middleware security headers chung trong create_app (main.py): X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options: nosniff cho response.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware chung trong create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app (main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff; không middleware nào đặt.

**Đề xuất sửa:** Thêm nosniff trong middleware security headers ở create_app (main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health trả JSON không có nosniff; tác động thấp nhưng cùng nguyên nhân thiếu middleware header.

**Đề xuất sửa:** Thêm nosniff trong middleware security headers ở create_app (main.py), áp dụng cho mọi route kể cả /health.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 65.3 s · 25 lần gọi LLM · 15 lần gọi công cụ · 123303 token vào / 10362 token ra · ≈ $0.2092 · chạm giới hạn: không</sub>
