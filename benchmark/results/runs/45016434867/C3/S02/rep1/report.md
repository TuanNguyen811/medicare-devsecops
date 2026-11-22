<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `6d5288d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | agent | IDOR: xuất bệnh án không kiểm tra quyền theo đối tượng | `app/medicare/record/export.py:35` | 0.95 |
| 🔴 TP | HIGH | agent | Path traversal / đọc file tùy ý qua tham số letterhead | `app/medicare/record/export.py:27` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.55 |

### Chi tiết

#### 🔴 TP · CRITICAL · IDOR: xuất bệnh án không kiểm tra quyền theo đối tượng — `app/medicare/record/export.py:35`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** `get_record_for_export` lấy bản ghi bằng `db.get(MedicalRecord, record_id)` và chỉ kiểm tra vai trò (DOCTOR/NURSE/PATIENT) ở router, không gọi hàm `policy.can_*` nào. Bất kỳ bác sĩ, y tá khác khoa hay bệnh nhân nào cũng xuất được bệnh án của người khác bằng cách đoán id. Vi phạm R-01, R-02, và R-15 (nên trả 404 khi không có quyền). Audit log còn ghi EXPORT_RECORD cho cả truy cập trái phép.

**Kịch bản khai thác:** Bệnh nhân A đăng nhập, lặp GET /records/1..N/export và tải chẩn đoán, ghi chú của mọi bệnh nhân khác.

**Đề xuất sửa:** Trong export.get_record_for_export, tái sử dụng cùng cơ chế như service.get_record_for: lấy patient rồi gọi hàm policy.can_view_record (policy.py) cho user; nếu không có quyền thì raise NotFound (404 giống bản ghi không tồn tại, R-15) và chỉ ghi audit sau khi đã được phép. Bổ sung test cho bác sĩ/y tá khác khoa và bệnh nhân khác.

#### 🔴 TP · HIGH · Path traversal / đọc file tùy ý qua tham số letterhead — `app/medicare/record/export.py:27`

CWE-22 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Tham số query `letterhead` do người dùng kiểm soát được nối trực tiếp vào đường dẫn `LETTERHEAD_DIR / name` mà không đối chiếu allowlist. Giá trị như `../../../../etc/passwd` hoặc đường dẫn tuyệt đối sẽ thoát khỏi thư mục letterheads. Nội dung file được đọc rồi chèn vào đầu phiếu (HTML/TXT) và trả về cho client, nên đây là đọc file tùy ý (ví dụ file cấu hình chứa SECRET_KEY, .env). Chỉ bắt FileNotFoundError nên còn gây lỗi 500 với thư mục.

**Kịch bản khai thác:** Người dùng đã đăng nhập (ví dụ bệnh nhân) gọi GET /records/{id}/export?format=txt&letterhead=../../../../etc/passwd và nhận nội dung file trong phần đầu của phiếu.

**Đề xuất sửa:** Trong export.py, không ghép đường dẫn từ input. Chỉ chấp nhận `name` nằm trong tập `letterheads()` (allowlist); nếu không thuộc allowlist thì dùng DEFAULT_LETTERHEAD. Có thể thêm kiểm tra `resolve()` nằm trong LETTERHEAD_DIR. Router export_record cũng nên validate tham số trước khi gọi read_letterhead.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP quan sát thiếu X-Frame-Options / frame-ancestors trên phản hồi của ứng dụng; không có bằng chứng mã nào cho thấy header được đặt. Ứng dụng y tế nên chống clickjacking.

**Đề xuất sửa:** Thêm middleware chung đặt `X-Frame-Options: DENY` và CSP `frame-ancestors 'none'` cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; trang đăng nhập là mục tiêu điển hình của clickjacking. Không có bằng chứng phản bác.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi phản hồi, gồm /login.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên GET /.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; tác động rất thấp nhưng sửa chung bằng middleware.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff cho mọi phản hồi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu `X-Content-Type-Options: nosniff` trên /login theo ZAP; không có header bảo mật chung được thấy trong mã.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt `X-Content-Type-Options: nosniff` cho mọi phản hồi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Ứng dụng chưa đặt Content-Security-Policy (cùng nguyên nhân với các cluster CSP khác); là thiếu hardening toàn cục, tác động thấp.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi phản hồi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi phản hồi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi phản hồi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi phản hồi.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 42.6 s · 14 lần gọi LLM · 13 lần gọi công cụ · 56841 token vào / 6663 token ra · ≈ $0.1872 · chạm giới hạn: không</sub>
