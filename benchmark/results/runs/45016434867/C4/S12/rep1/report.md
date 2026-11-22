<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `d3be9b5`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | PHI/PII (CCCD, số bảo hiểm, chẩn đoán) bị ghi vào log ứng dụng | `app/medicare/record/service.py:22` | 0.90 |
| 🔴 TP | MEDIUM | agent | Job compaction xóa bản ghi audit VIEW_RECORD (mất tính toàn vẹn nhật ký audit) | `app/medicare/audit/maintenance.py:41` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · PHI/PII (CCCD, số bảo hiểm, chẩn đoán) bị ghi vào log ứng dụng — `app/medicare/record/service.py:22`

CWE-532 · OWASP A09 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** _log_event ghi national_id, insurance_number, diagnosis và patient_code vào log JSON mỗi lần xem/sửa hồ sơ; log được gửi tới Loki, ngoài kiểm soát truy cập của policy.can_*, và không bị giới hạn retention như bảng audit.

**Kịch bản khai thác:** Bất kỳ ai có quyền đọc log (Loki, log agent) đều thấy CCCD, số bảo hiểm và chẩn đoán của bệnh nhân mà không cần quyền hồ sơ.

**Đề xuất sửa:** Trong record/service.py::_log_event chỉ ghi các ID nội bộ (user_id, role, record_id); bỏ national_id, insurance_number, diagnosis, patient_code. Có thể thêm bộ lọc trong JsonFormatter (common/logs.py) để che các khóa nhạy cảm.

#### 🔴 TP · MEDIUM · Job compaction xóa bản ghi audit VIEW_RECORD (mất tính toàn vẹn nhật ký audit) — `app/medicare/audit/maintenance.py:41`

CWE-779 · OWASP A09 · độ tin cậy 0.60 · nguồn: agent

**Phân tích:** compact_repeated_views thực hiện DELETE trên AuditLog. Dùng lag theo cửa sổ trượt nên chuỗi xem liên tục (mỗi lần cách <30 phút) bị xóa gần hết, chỉ giữ lần đầu; mất thời điểm truy cập thực tế vào hồ sơ bệnh án, trái yêu cầu audit append-only.

**Kịch bản khai thác:** Người dùng xem hồ sơ liên tục suốt ca (mỗi lần cách vài phút); job đêm xóa mọi lần xem trừ lần đầu, nên điều tra truy cập trái phép không còn thấy thời gian thực tế.

**Đề xuất sửa:** Không DELETE bản ghi audit; thay vào đó giảm ghi trùng tại nguồn trong audit.log_access (throttle) hoặc chuyển sang lưu trữ/archive có kiểm soát. Nếu vẫn gộp, dùng cửa sổ cố định và cần phê duyệt tuân thủ, tài khoản DB của job chỉ có quyền hạn chế.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app không có middleware nào thêm header bảo mật (X-Frame-Options / CSP frame-ancestors); tìm kiếm trong repo không thấy header nào.

**Đề xuất sửa:** Thêm middleware trong create_app (main.py) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; không có middleware đặt header trong create_app.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong main.py: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng (search không thấy Content-Security-Policy).

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self'; frame-ancestors 'none') trong middleware ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên mọi response.

**Đề xuất sửa:** Thêm nosniff trong middleware header chung ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health cũng không có nosniff vì không có middleware toàn cục; rủi ro thấp nhưng sửa chung được.

**Đề xuất sửa:** Middleware header toàn cục trong main.py sẽ bao phủ cả /health.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 55.9 s · 25 lần gọi LLM · 15 lần gọi công cụ · 97794 token vào / 9433 token ra · ≈ $0.1798 · chạm giới hạn: không</sub>
