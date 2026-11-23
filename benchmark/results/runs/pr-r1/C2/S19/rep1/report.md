<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `4b66115`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | IDOR: y tá xem danh sách bệnh nhân của khoa khác qua department_id | `app/medicare/patient/router.py:100` | agent | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: y tá xem danh sách bệnh nhân của khoa khác qua department_id — `app/medicare/patient/router.py:100`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /ward/patients nhận department_id từ client và dùng trực tiếp, không kiểm tra bằng policy.can_*. Theo ma trận, y tá chỉ xem bệnh nhân cùng khoa. Ngoài ra danh sách còn trả họ tên, ngày sinh, giới tính, BS phụ trách, ngày khám gần nhất, và link tới hồ sơ của bệnh nhân khoa khác.

**Kịch bản khai thác:** Y tá khoa NOI gọi GET /ward/patients?department_id=2 (hoặc duyệt từng id) và nhận danh sách bệnh nhân mọi khoa. Dropdown còn liệt kê tất cả khoa.

**Đề xuất sửa:** Trong router.ward_patients, bỏ việc tin department_id của client: dùng user.department_id của y tá (nếu rỗng trả danh sách rỗng). Nếu vẫn cần tham số, chỉ chấp nhận khi bằng user.department_id, hoặc lọc từng bệnh nhân bằng policy.can_view_patient(user, p) trước khi đưa vào rows. Với khoa không được phép trả 404 (R-15), và template chỉ liệt kê khoa của y tá.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Không tìm thấy X-Frame-Options hay frame-ancestors ở bất kỳ đâu trong repo, nên ứng dụng thiếu header chống clickjacking. | Thêm middleware security headers trong app chính: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'). |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Repo không đặt Content-Security-Policy. | Thêm CSP trong middleware security headers chung (default-src 'self', frame-ancestors 'none'). |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Không có X-Content-Type-Options trong repo. | Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Không có X-Content-Type-Options trong repo. | Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 31.5 s · 16 lần gọi LLM · 15 lần gọi công cụ · 70944 token vào / 4486 token ra · ≈ $0.1159 · chạm giới hạn: không</sub>
