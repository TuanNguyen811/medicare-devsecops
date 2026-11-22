<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 2 lỗi cần sửa (2 do Agent tự tìm, công cụ quét không báo)

📋 9 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `d5e113c`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | Export CSV mở cho DOCTOR/NURSE và lộ CCCD, BHYT không che | `app/medicare/patient/router.py:102` | agent | 0.90 |
| 🔴 TP | MEDIUM | Export CSV không trung hòa ô công thức (CSV injection) | `app/medicare/common/csv_export.py:15` | agent | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · Export CSV mở cho DOCTOR/NURSE và lộ CCCD, BHYT không che — `app/medicare/patient/router.py:102`

CWE-639 · OWASP A01 · vi phạm R-11 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /patients/export dùng staff_user (gồm DOCTOR, NURSE) trong khi ma trận phân quyền chỉ cho ADMIN và RECEPTIONIST xuất danh sách. Hơn nữa national_id và insurance_number được xuất thô, không che, vi phạm R-11 và R-19. Bác sĩ/y tá chỉ thấy CCCD bị che trên giao diện, nhưng qua CSV lấy được đầy đủ.

**Kịch bản khai thác:** Y tá đăng nhập, gọi GET /patients/export và nhận CCCD, mã BHYT đầy đủ của mọi bệnh nhân cùng khoa.

**Đề xuất sửa:** Đổi dependency của export_patients sang editor_user (require_roles(*EDITORS) = RECEPTIONIST, ADMIN). Ngoài ra dùng cơ chế che định danh hiện có của R-11 (hàm _identifiers/mask) khi dựng rows để CCCD và BHYT chỉ đầy đủ với vai trò được phép.

#### 🔴 TP · MEDIUM · Export CSV không trung hòa ô công thức (CSV injection) — `app/medicare/common/csv_export.py:15`

CWE-1236 · OWASP A05 · vi phạm R-19 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** csv_response ghi trực tiếp str(value) vào csv.writer mà không xử lý ô bắt đầu bằng =, +, -, @, tab hoặc xuống dòng. Các trường như full_name, address do lễ tân nhập có thể chứa công thức.

**Kịch bản khai thác:** Người tạo hồ sơ nhập họ tên '=HYPERLINK(...)' hoặc '=cmd|...'; khi admin mở file CSV bằng Excel, công thức được thực thi, có thể làm lộ dữ liệu hoặc chạy lệnh.

**Đề xuất sửa:** Trong app/medicare/common/csv_export.py, thêm hàm trung hòa ô: nếu chuỗi bắt đầu bằng '=', '+', '-', '@', tab hoặc '\r'/'\n' thì thêm tiền tố dấu nháy đơn ('). Áp dụng cho mọi ô (kể cả header) trước khi writerow trong csv_response.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 9</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Tìm trong repo không có chỗ nào đặt X-Frame-Options hoặc frame-ancestors, nên ứng dụng thật sự thiếu header chống clickjacking. | Thêm middleware toàn cục trong app factory để đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `GET /login`, `POST /appointments`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Repo không đặt X-Content-Type-Options ở đâu cả. | Trong middleware security headers toàn cục, đặt X-Content-Type-Options: nosniff cho mọi response. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Repo không đặt X-Content-Type-Options. | Đặt X-Content-Type-Options: nosniff trong middleware toàn cục. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 41.5 s · 18 lần gọi LLM · 17 lần gọi công cụ · 119160 token vào / 5902 token ra · ≈ $0.1386 · chạm giới hạn: không</sub>
