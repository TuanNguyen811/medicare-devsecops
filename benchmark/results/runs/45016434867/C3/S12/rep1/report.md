<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `d3be9b5`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Job bảo trì xóa bản ghi audit log VIEW_RECORD | `app/medicare/audit/maintenance.py:40` | 0.90 |
| 🔴 TP | HIGH | agent | Ghi PII (CCCD, mã BHYT, chẩn đoán) vào log ứng dụng | `app/medicare/record/service.py:21` | 0.97 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |

### Chi tiết

#### 🔴 TP · HIGH · Job bảo trì xóa bản ghi audit log VIEW_RECORD — `app/medicare/audit/maintenance.py:40`

CWE-778 · OWASP A09 · vi phạm R-06 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** compact_repeated_views thực hiện delete(AuditLog) trên bảng audit, trái R-06 (audit log chỉ được thêm, không xóa) và làm mất dấu vết từng lần truy cập bệnh án theo R-05 (mỗi lần xem phải có một bản ghi). Chỉ giữ lần xem đầu mỗi burst nên không thể chứng minh các lần xem sau, ví dụ khi kẻ xấu mở lại hồ sơ nhiều lần.

**Kịch bản khai thác:** Người truy cập trái phép liên tục xem hồ sơ trong cửa sổ 30 phút; các lần xem lặp bị xóa khỏi audit, làm điều tra sự cố thiếu bằng chứng về thời điểm và số lần truy cập.

**Đề xuất sửa:** Bỏ job xóa dữ liệu trong app/medicare/audit/maintenance.py. Nếu cần giảm khối lượng, giữ audit append-only: lưu trữ/archive sang bảng hoặc kho chỉ-ghi, hoặc giảm tần suất ghi ở audit.log_access với cơ chế được phê duyệt, và thu hồi quyền DELETE trên bảng audit của DB user ứng dụng.

#### 🔴 TP · HIGH · Ghi PII (CCCD, mã BHYT, chẩn đoán) vào log ứng dụng — `app/medicare/record/service.py:21`

CWE-532 · OWASP A09 · vi phạm R-10 · độ tin cậy 0.97 · nguồn: agent

**Phân tích:** _log_event đưa national_id, insurance_number và diagnosis vào extra=; JsonFormatter xuất mọi trường extra thành khóa cấp cao nhất nên PII đầy đủ (không che) được ghi vào log mỗi lần xem/sửa bệnh án và gửi sang Loki. Vi phạm R-10 và R-11, đồng thời làm lộ dữ liệu cho người không có quyền xem (R-12).

**Kịch bản khai thác:** Bất kỳ ai có quyền đọc log/Loki (vận hành, support) đọc được CCCD, mã BHYT và chẩn đoán của bệnh nhân mà không qua policy.can_*; rò rỉ log cũng làm lộ toàn bộ dữ liệu này.

**Đề xuất sửa:** Trong _log_event (app/medicare/record/service.py) bỏ các trường national_id, insurance_number và diagnosis; chỉ giữ định danh không nhạy cảm như user_id, role, record_id và patient_code (hoặc patient_id). Cân nhắc thêm allowlist các khóa extra trong JsonFormatter (app/medicare/common/logs.py) để PII không thể lọt vào log.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app chỉ thêm middleware Errors, Session, Metrics; không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors, nên trang HTML có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F1: trang /login (form đăng nhập) không có header chống framing do app không có middleware đặt header bảo mật.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py): X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options: nosniff.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware security headers ở create_app (app/medicare/main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health trả JSON và không có X-Content-Type-Options; thiếu header toàn cục, ảnh hưởng rất thấp trên endpoint này nhưng sửa chung được.

**Đề xuất sửa:** Middleware security headers toàn cục trong create_app (app/medicare/main.py) đặt nosniff cho mọi route, gồm /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff; /login thiếu header này (và CSP).

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers trong create_app (app/medicare/main.py) đặt X-Content-Type-Options: nosniff và CSP cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu (không có middleware); đây là thiếu hardening toàn cục, mức ảnh hưởng thấp với response POST.

**Đề xuất sửa:** Thêm CSP toàn cục qua middleware security headers trong create_app (app/medicare/main.py), ví dụ default-src 'self'.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F6: không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP toàn cục qua middleware security headers trong create_app (app/medicare/main.py).

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F6: không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP toàn cục qua middleware security headers trong create_app (app/medicare/main.py).

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Cùng nguyên nhân với F6: không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP toàn cục qua middleware security headers trong create_app (app/medicare/main.py).

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 41.7 s · 13 lần gọi LLM · 12 lần gọi công cụ · 47315 token vào / 6913 token ra · ≈ $0.1702 · chạm giới hạn: không</sub>
