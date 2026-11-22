<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 2 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 9 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `71ec2a7`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | py/path-injection (codeql) | `app/medicare/record/export.py:30` | codeql | 0.95 |
| 🔴 TP | HIGH | IDOR: export_record không kiểm tra policy.can_view_record | `app/medicare/record/export.py:38` | agent | 0.93 |

### Chi tiết

#### 🔴 TP · HIGH · py/path-injection (codeql) — `app/medicare/record/export.py:30`

CWE-22 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.95 · nguồn: codeql

**Phân tích:** Tham số query `letterhead` do người dùng kiểm soát được nối trực tiếp vào `LETTERHEAD_DIR / name` rồi đọc bằng `read_text`, không có allowlist. Nội dung file đọc được sẽ được chèn vào phản hồi (header của bệnh án), nên có thể đọc file tuỳ ý (`../../...`, hoặc đường dẫn tuyệt đối) có đuôi bất kỳ. Vi phạm R-14.

**Kịch bản khai thác:** Bác sĩ/y tá/bệnh nhân gọi GET /records/1/export?letterhead=../../../../etc/passwd (hoặc file .env) và nhận nội dung file trong phần đầu của bản xuất.

**Đề xuất sửa:** Trong `read_letterhead` (export.py), chỉ chấp nhận `name` nếu nằm trong allowlist `letterheads()` (so sánh chính xác với tên file liệt kê); nếu không thì dùng DEFAULT_LETTERHEAD. Không nối đường dẫn từ input thô; có thể kiểm tra thêm resolve() nằm trong LETTERHEAD_DIR.

#### 🔴 TP · HIGH · IDOR: export_record không kiểm tra policy.can_view_record — `app/medicare/record/export.py:38`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.93 · nguồn: agent

**Phân tích:** `get_record_for_export` chỉ gọi `db.get(MedicalRecord, record_id)` rồi trả bệnh án; route chỉ yêu cầu vai trò DOCTOR/NURSE/PATIENT mà không gọi `policy.can_view_record(user, patient)`. Bất kỳ bác sĩ/y tá khoa khác hoặc bệnh nhân khác đều tải được bệnh án của người khác (chẩn đoán, ghi chú). Vi phạm R-01, R-02, R-15 (nên trả 404 thống nhất). Test `test_patient_exports_own_record` chỉ kiểm tra trường hợp hợp lệ. Ngoài ra audit log được ghi trước khi kiểm tra quyền.

**Kịch bản khai thác:** Bệnh nhân A đăng nhập và gọi GET /records/{id}/export?format=txt với id bệnh án của bệnh nhân B, nhận toàn bộ chẩn đoán và triệu chứng của B.

**Đề xuất sửa:** Trong `get_record_for_export` dùng lại `service.get_record_for(db, user, record_id, ip)` hoặc gọi `policy.can_view_record(user, record.patient)` và raise NotFound (404 giống hệt bản ghi không tồn tại) khi không được phép, trước khi ghi audit/trả dữ liệu. Thêm test cho bệnh nhân/bác sĩ/y tá khác khoa.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 9</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Tìm trong repo không thấy middleware nào đặt X-Frame-Options hoặc frame-ancestors; main.py chỉ có CatchAllErrors, Session, Metrics. Ứng dụng y tế có thể bị clickjacking. | Thêm middleware security headers trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi phản hồi. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Không có X-Content-Type-Options: nosniff được đặt ở bất kỳ đâu. | Thêm X-Content-Type-Options: nosniff vào middleware security headers trong main.py. |
| xác nhận | LOW | 10038 (zap) | `GET /login`, `POST /appointments`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có middleware đặt X-Content-Type-Options: nosniff trong repo. | Thêm X-Content-Type-Options: nosniff vào middleware security headers trong main.py. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 39.5 s · 17 lần gọi LLM · 16 lần gọi công cụ · 99002 token vào / 5879 token ra · ≈ $0.0996 · chạm giới hạn: không</sub>
