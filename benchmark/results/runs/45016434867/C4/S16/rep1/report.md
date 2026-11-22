<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `5aac359`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | IDOR: can_reschedule_appointment thiếu kiểm tra quyền sở hữu của bệnh nhân | `app/medicare/policy.py:119` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/reschedule:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: can_reschedule_appointment thiếu kiểm tra quyền sở hữu của bệnh nhân — `app/medicare/policy.py:119`

CWE-639 · OWASP A01 · vi phạm R-13 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Với vai trò PATIENT, hàm chỉ kiểm tra user.patient_id is not None và status == REQUESTED, không so sánh user.patient_id với appt.patient_id (khác với can_cancel_appointment). Vì vậy mọi bệnh nhân đều đổi lịch được lịch hẹn REQUESTED của bệnh nhân khác qua GET/POST /appointments/{id}/reschedule (get_for_reschedule dùng đúng policy này). Trang reschedule.html còn lộ tên và mã bệnh nhân khác.

**Kịch bản khai thác:** Bệnh nhân A đoán/duyệt appointment_id tuần tự, mở GET /appointments/<id của B>/reschedule để xem tên, mã bệnh nhân B, rồi POST thời gian mới để dời hoặc phá lịch hẹn của B.

**Đề xuất sửa:** Trong policy.can_reschedule_appointment, nhánh PATIENT phải thêm điều kiện user.patient_id == appt.patient_id, giống can_cancel_appointment. Bổ sung test_policy cho trường hợp bệnh nhân khác (relation 'other') phải trả về False và test route trả 404 khi bệnh nhân đổi lịch của người khác.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không tìm thấy nơi nào trong repo đặt X-Frame-Options hay frame-ancestors, nên ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers toàn cục trong app (main/app factory): X-Frame-Options: DENY và CSP có frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking; không có cấu hình header nào trong repo.

**Đề xuất sửa:** Dùng middleware security headers toàn cục: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware toàn cục (default-src 'self', frame-ancestors 'none'), áp dụng cho mọi response gồm cả POST và trang lỗi.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/reschedule:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo; route reschedule mới cũng không có header này.

**Đề xuất sửa:** Thêm CSP trong middleware toàn cục để áp dụng cho cả route reschedule.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options; không có middleware đặt header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** /health cũng thiếu X-Content-Type-Options; không có middleware đặt header.

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 32.7 s · 15 lần gọi LLM · 14 lần gọi công cụ · 81039 token vào / 4813 token ra · ≈ $0.1167 · chạm giới hạn: không</sub>
