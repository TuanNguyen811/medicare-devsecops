<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 11 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `9b7d84d`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | Race condition: đặt lịch trùng giờ do bỏ unique index và chỉ kiểm tra overlap ở tầng ứng dụng | `app/medicare/appointment/service.py:133` | agent | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · Race condition: đặt lịch trùng giờ do bỏ unique index và chỉ kiểm tra overlap ở tầng ứng dụng — `app/medicare/appointment/service.py:133`

CWE-362 · OWASP A06 · vi phạm R-13 · độ tin cậy 0.80 · nguồn: agent

**Phân tích:** PR bỏ unique index uq_doctor_slot_active, vốn là ràng buộc DB chống trùng giờ. Thay vào đó, book() chỉ SELECT _active_around rồi INSERT, không có khóa hay ràng buộc. Hai request đồng thời cho cùng bác sĩ và cùng giờ đều thấy không có xung đột và đều insert thành công. Điều này vi phạm R-13 (một bác sĩ không có hai lịch hẹn còn hiệu lực trùng giờ).

**Kịch bản khai thác:** Hai request POST /appointments/quick (hoặc /appointments) gửi cùng lúc cho cùng bác sĩ và cùng khung giờ. Cả hai cùng vượt qua bước kiểm tra, nên bác sĩ bị đặt trùng giờ.

**Đề xuất sửa:** Trong service.book(), khóa hàng bác sĩ bằng SELECT ... FOR UPDATE (db.get(User, doctor_id, with_for_update=True)) trước khi gọi _active_around, để các lần đặt lịch cho cùng bác sĩ được tuần tự hóa. Cách khác là thêm exclusion constraint của PostgreSQL (btree_gist) trên doctor_id và tstzrange(scheduled_at, scheduled_at + duration) với điều kiện status <> 'CANCELLED', trong migration 0004. Bắt lỗi vi phạm constraint và chuyển thành Conflict.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 11</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | create_app trong app/medicare/main.py chỉ thêm CatchAllErrors, Session, Metrics middleware. Toàn repo không có X-Frame-Options, CSP hay frame-ancestors, nên trang HTML có thể bị nhúng vào iframe (clickjacking). | Thêm một middleware security headers trong create_app (app/medicare/main.py) để đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/quick`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | App không đặt Content-Security-Policy ở bất kỳ đâu (không có kết quả khi tìm trong repo). | Thêm header Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong security headers middleware ở main.py. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options, cùng nguyên nhân gốc với F5. | Đặt X-Content-Type-Options: nosniff trong security headers middleware chung. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Không có middleware nào đặt X-Content-Type-Options: nosniff (tìm toàn repo không thấy). Mức thực tế thấp. | Trong security headers middleware ở main.py, đặt X-Content-Type-Options: nosniff cho mọi response. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 57.4 s · 30 lần gọi LLM · 18 lần gọi công cụ · 185088 token vào / 9116 token ra · ≈ $0.2295 · chạm giới hạn: không</sub>
