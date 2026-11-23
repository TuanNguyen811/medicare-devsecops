<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `aa5c068`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | IDOR: can_reschedule_appointment không kiểm tra lịch hẹn thuộc về bệnh nhân | `app/medicare/policy.py:119` | agent | 0.95 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: can_reschedule_appointment không kiểm tra lịch hẹn thuộc về bệnh nhân — `app/medicare/policy.py:119`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Với vai trò PATIENT, hàm chỉ kiểm tra user.patient_id is not None và trạng thái REQUESTED, thiếu so sánh user.patient_id == appt.patient_id (như can_cancel_appointment). Bất kỳ bệnh nhân nào cũng đổi được lịch REQUESTED của người khác qua GET/POST /appointments/{id}/reschedule; trang reschedule.html còn lộ mã và tên bệnh nhân khác (appt.patient.code, full_name). Test chỉ kiểm tra "self" nên không phát hiện lỗi.

**Kịch bản khai thác:** Bệnh nhân A đăng nhập, duyệt id lịch hẹn tuần tự, mở /appointments/{id_của_B}/reschedule thì xem được tên và mã bệnh nhân B. POST thời gian mới sẽ dời lịch của B, hoặc chiếm slot của bác sĩ.

**Đề xuất sửa:** Trong policy.can_reschedule_appointment, nhánh PATIENT phải thêm điều kiện user.patient_id == appt.patient_id, giống can_cancel_appointment. Bổ sung test_policy với bệnh nhân khác (relation 'other') kỳ vọng False, và test route trả 404 khi bệnh nhân khác truy cập.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | create_app chỉ thêm CatchAllErrors, Session và Metrics middleware; không có middleware nào đặt X-Frame-Options hay CSP frame-ancestors. Ứng dụng y tế có thể bị clickjacking. | Thêm middleware trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/confirm`, `POST /appointments/{appointment_id}/reschedule`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có CSP nào được đặt trong ứng dụng (tìm kiếm không thấy Content-Security-Policy). | Thêm Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware header bảo mật ở create_app, main.py. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options; không có middleware đặt header này. | Đặt X-Content-Type-Options: nosniff trong middleware header bảo mật ở create_app. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Không có code nào đặt X-Content-Type-Options: nosniff. | Trong middleware header bảo mật ở create_app (main.py), đặt X-Content-Type-Options: nosniff cho mọi response. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 40.8 s · 16 lần gọi LLM · 15 lần gọi công cụ · 126651 token vào / 6313 token ra · ≈ $0.1592 · chạm giới hạn: không</sub>
