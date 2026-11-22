<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `5aac359`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | IDOR: can_reschedule_appointment không kiểm tra bệnh nhân sở hữu lịch hẹn | `app/medicare/policy.py:119` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/reschedule:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: can_reschedule_appointment không kiểm tra bệnh nhân sở hữu lịch hẹn — `app/medicare/policy.py:119`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Với vai trò PATIENT, hàm chỉ kiểm tra user.patient_id is not None và status == REQUESTED, không so sánh user.patient_id với appt.patient_id (khác với can_cancel_appointment). Vì vậy mọi bệnh nhân đều đổi được lịch REQUESTED của bệnh nhân khác qua POST /appointments/{id}/reschedule, và GET cùng route làm lộ mã và tên bệnh nhân khác trong reschedule.html. Vi phạm R-01 và R-13. Các test chỉ kiểm tra 'self' nên không phát hiện lỗi này.

**Kịch bản khai thác:** Bệnh nhân A đăng nhập, duyệt ID lịch hẹn tuần tự, gọi GET /appointments/{id}/reschedule để xem tên và mã bệnh nhân B, rồi POST đổi giờ lịch của B (đang REQUESTED), gây gián đoạn khám và lộ PII.

**Đề xuất sửa:** Trong policy.can_reschedule_appointment, nhánh PATIENT phải yêu cầu user.patient_id is not None và user.patient_id == appt.patient_id và appt.status == REQUESTED (giống can_cancel_appointment). Bổ sung test_policy cho trường hợp bệnh nhân khác (relation 'other') phải trả về False, và test route trả 404 khi bệnh nhân đổi lịch của người khác.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** ZAP (DAST) quan sát thấy phản hồi thiếu X-Frame-Options/frame-ancestors. Không có bằng chứng nào trong mã được cung cấp cho thấy có middleware đặt header bảo mật nên coi là thật.

**Đề xuất sửa:** Thêm middleware toàn cục cho FastAPI đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; trang đăng nhập đặc biệt dễ bị framing. Không có bằng chứng về header trong mã.

**Đề xuất sửa:** Dùng middleware security headers chung: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Phản hồi HTML thiếu Content-Security-Policy; ứng dụng chứa dữ liệu y tế nên CSP là lớp phòng thủ cần có.

**Đề xuất sửa:** Đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/reschedule:0`

CWE-693 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Route reschedule mới trả HTML không có CSP; cùng nguyên nhân thiếu header toàn cục.

**Đề xuất sửa:** Đặt CSP trong middleware toàn cục để áp dụng cho mọi route, gồm cả reschedule.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** POST /patients thiếu CSP, cùng nguyên nhân thiếu header toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** POST /patients/{id}/edit thiếu CSP, cùng nguyên nhân thiếu header toàn cục.

**Đề xuất sửa:** Thêm CSP trong middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; rủi ro thấp nhưng sửa chung bằng middleware.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên /login, thiếu cấu hình header toàn cục.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 29.9 s · 12 lần gọi LLM · 11 lần gọi công cụ · 68191 token vào / 4464 token ra · ≈ $0.1847 · chạm giới hạn: không</sub>
