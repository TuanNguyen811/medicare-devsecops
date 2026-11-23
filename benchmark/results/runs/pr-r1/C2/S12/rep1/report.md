<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 2 lỗi cần sửa (2 do Agent tự tìm, công cụ quét không báo)

📋 9 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `6cd3621`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | Job bảo trì xóa dòng audit log, phá vỡ tính bất biến | `app/medicare/audit/maintenance.py:41` | agent | 0.90 |
| 🔴 TP | HIGH | Ghi PII (CCCD, mã BHYT, chẩn đoán) vào log ứng dụng | `app/medicare/record/service.py:21` | agent | 0.97 |

### Chi tiết

#### 🔴 TP · HIGH · Job bảo trì xóa dòng audit log, phá vỡ tính bất biến — `app/medicare/audit/maintenance.py:41`

CWE-778 · OWASP A09 · vi phạm R-06 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** compact_repeated_views thực hiện delete(AuditLog) các dòng VIEW_RECORD lặp. R-06 quy định audit log chỉ được thêm, không có chức năng sửa hay xóa, và R-05 yêu cầu ghi mọi lần truy cập bệnh án. Việc xóa làm mất dấu vết các lần xem lặp lại, gây khó điều tra truy cập trái phép; job cũng chạy với quyền DB đầy đủ nên là đường xóa bằng chứng.

**Kịch bản khai thác:** Người dùng nội bộ xem hồ sơ nhiều lần; job xóa các lần xem sau trong cửa sổ 30 phút nên audit log không phản ánh đầy đủ thời điểm và số lần truy cập khi điều tra sự cố.

**Đề xuất sửa:** Bỏ job xóa trong audit/maintenance.py. Giảm khối lượng bằng cách chống ghi trùng ở audit.log_access hoặc dùng partition/archival sang kho chỉ-ghi (không xóa), và thu hồi quyền DELETE/UPDATE trên bảng audit cho tài khoản ứng dụng.

#### 🔴 TP · HIGH · Ghi PII (CCCD, mã BHYT, chẩn đoán) vào log ứng dụng — `app/medicare/record/service.py:21`

CWE-532 · OWASP A09 · vi phạm R-10 · độ tin cậy 0.97 · nguồn: agent

**Phân tích:** _log_event đưa national_id, insurance_number và diagnosis vào extra=; JsonFormatter xuất mọi trường extra thành khóa cấp cao nhất ra stderr rồi được log agent đẩy lên Loki. Điều này vi phạm R-10 (không ghi PII vào log) và còn làm lộ CCCD/BHYT đầy đủ cho cả bác sĩ/y tá (vốn bị che theo R-11) và cả người đọc log.

**Kịch bản khai thác:** Người có quyền đọc log (Loki) mà không có quyền xem bệnh án lấy được CCCD, mã BHYT và chẩn đoán của bệnh nhân chỉ bằng cách lọc sự kiện record.view / record.update.

**Đề xuất sửa:** Trong record/service.py, hàm _log_event: bỏ national_id, insurance_number và diagnosis khỏi extra. Chỉ ghi định danh không nhạy cảm như user_id, role, record_id (và patient_id nội bộ nếu cần). Có thể thêm danh sách deny cho khóa PII trong JsonFormatter (common/logs.py) và thêm test khẳng định log không chứa các trường này.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 9</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | create_app không có middleware nào đặt header bảo mật; tìm trong repo không thấy X-Frame-Options/CSP frame-ancestors. | Thêm một middleware trong main.py (create_app) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `GET /login`, `POST /appointments`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có code nào đặt X-Content-Type-Options trong ứng dụng. | Trong middleware header bảo mật chung ở main.py, đặt X-Content-Type-Options: nosniff cho mọi response. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Không có middleware đặt X-Content-Type-Options trong create_app. | Đặt X-Content-Type-Options: nosniff trong middleware header bảo mật chung ở main.py. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 39.4 s · 16 lần gọi LLM · 15 lần gọi công cụ · 86554 token vào / 5811 token ra · ≈ $0.1340 · chạm giới hạn: không</sub>
