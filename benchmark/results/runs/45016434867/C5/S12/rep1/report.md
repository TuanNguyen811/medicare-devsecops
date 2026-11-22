<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `d3be9b5`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Job compact xóa audit log, vi phạm tính bất biến | `app/medicare/audit/maintenance.py:41` | 0.90 |
| 🔴 TP | HIGH | agent | Ghi PII (CCCD, mã BHYT, chẩn đoán) vào log | `app/medicare/record/service.py:28` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Job compact xóa audit log, vi phạm tính bất biến — `app/medicare/audit/maintenance.py:41`

CWE-778 · OWASP A09 · vi phạm R-06 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** compact_repeated_views thực hiện DELETE trên bảng audit_log. R-06 yêu cầu audit log chỉ thêm, không xóa; R-05 yêu cầu ghi mọi lần xem bệnh án. Xóa các lượt xem lặp làm mất dấu vết truy cập.

**Kịch bản khai thác:** CronJob hằng đêm xóa các dòng VIEW_RECORD; sau sự cố mất các lần truy cập sau lần đầu trong mỗi cụm 30 phút, kẻ truy cập trái phép che được hoạt động.

**Đề xuất sửa:** Bỏ chức năng xóa audit log trong maintenance.py. Giảm khối lượng bằng dedupe lúc ghi ở audit.log_access hoặc archive/partition bất biến thay vì DELETE.

#### 🔴 TP · HIGH · Ghi PII (CCCD, mã BHYT, chẩn đoán) vào log — `app/medicare/record/service.py:28`

CWE-532 · OWASP A09 · vi phạm R-10 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** _log_event đưa national_id, insurance_number và diagnosis vào extra=; JsonFormatter đẩy mọi trường extra thành key cấp cao nhất và gửi tới Loki. Đây là PII/dữ liệu lâm sàng bị cấm ghi log theo R-10, đồng thời bỏ qua việc che CCCD/BHYT (R-11).

**Kịch bản khai thác:** Bất kỳ ai đọc được log (Loki, vận hành) thu được CCCD, mã BHYT, chẩn đoán đầy đủ mỗi lần mở/sửa bệnh án.

**Đề xuất sửa:** Trong _log_event (app/medicare/record/service.py) bỏ national_id, insurance_number và diagnosis; chỉ giữ user_id, role, record_id, patient_code.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có mã nào trong repo đặt X-Frame-Options hay frame-ancestors; create_app chỉ thêm CatchAllErrorsMiddleware, SessionMiddleware, MetricsMiddleware. Ứng dụng dễ bị clickjacking.

**Đề xuất sửa:** Thêm một middleware bảo mật trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking; không có mã nào đặt header này trong repo.

**Đề xuất sửa:** Dùng cùng middleware security headers trong create_app (app/medicare/main.py): X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có mã nào đặt X-Content-Type-Options: nosniff trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers ở create_app (app/medicare/main.py) đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Trong middleware security headers ở create_app (app/medicare/main.py) đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py) để đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py) để đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có header Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py) để đặt Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có mã nào đặt X-Content-Type-Options: nosniff trong repo.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware security headers ở create_app (app/medicare/main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có mã nào đặt X-Content-Type-Options: nosniff trong repo, kể cả cho /health.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware security headers ở create_app (app/medicare/main.py), áp dụng cho cả /health.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 53.3 s · 20 lần gọi LLM · 17 lần gọi công cụ · 149626 token vào / 7347 token ra · ≈ $0.1685 · chạm giới hạn: không</sub>
