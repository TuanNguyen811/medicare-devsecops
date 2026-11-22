<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 13 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 3 phát hiện mới do Agent tự tìm · commit `6d5288d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Path traversal qua tham số letterhead | `app/medicare/record/export.py:28` | 0.90 |
| 🔴 TP | HIGH | agent | Export bệnh án không kiểm tra quyền đối tượng (IDOR) | `app/medicare/record/export.py:40` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |
| 🔴 TP | LOW | agent | Header Content-Disposition/HTML: xuất HTML không chống XSS rõ ràng cho dữ liệu letterhead đọc tùy ý | `app/medicare/record/router.py:139` | 0.40 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Path traversal qua tham số letterhead — `app/medicare/record/export.py:28`

CWE-22 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Tham số query letterhead do người dùng cung cấp được nối thẳng vào LETTERHEAD_DIR / name mà không đối chiếu allowlist. Có thể dùng ../ hoặc đường dẫn tuyệt đối để đọc file UTF-8 bất kỳ trên server (ví dụ ../../../.env), nội dung được chèn vào phần đầu của file xuất. Vi phạm R-14.

**Kịch bản khai thác:** GET /records/1/export?format=txt&letterhead=../../../../.env trả về nội dung .env gồm SECRET_KEY và thông tin DB.

**Đề xuất sửa:** Trong export.read_letterhead, chỉ chấp nhận name nằm trong tập letterheads() (allowlist); nếu không thì dùng DEFAULT_LETTERHEAD. Có thể thêm kiểm tra resolve() nằm trong LETTERHEAD_DIR.

#### 🔴 TP · HIGH · Export bệnh án không kiểm tra quyền đối tượng (IDOR) — `app/medicare/record/export.py:40`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** get_record_for_export chỉ db.get(MedicalRecord) rồi trả về; không gọi policy.can_view_record. Route chỉ kiểm tra vai trò (DOCTOR/NURSE/PATIENT), nên bất kỳ bác sĩ/y tá khác khoa hay bệnh nhân khác đều tải được bệnh án của người khác bằng cách đổi record_id. Vi phạm R-01, R-02, R-15; còn ghi audit trước khi kiểm tra quyền.

**Kịch bản khai thác:** Bệnh nhân A đăng nhập, gọi GET /records/<id của B>/export và nhận toàn bộ chẩn đoán, ghi chú của bệnh nhân B.

**Đề xuất sửa:** Trong export.get_record_for_export, dùng cùng đường kiểm tra như service.get_record_for (policy.can_view_record / can_view_patient); nếu không có quyền thì raise NotFound giống hệt bản ghi không tồn tại (R-15), và chỉ ghi audit sau khi kiểm tra quyền thành công.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong code không thấy X-Frame-Options hay frame-ancestors; ứng dụng không đặt header chống clickjacking.

**Đề xuất sửa:** Thêm middleware đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; không có middleware đặt header trong code.

**Đề xuất sửa:** Thêm middleware đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy được đặt ở ứng dụng.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt (default-src 'self') cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy được đặt ở ứng dụng.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt (default-src 'self') cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy được đặt ở ứng dụng.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt (default-src 'self') cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy được đặt ở ứng dụng.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt (default-src 'self') cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy được đặt ở ứng dụng.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt (default-src 'self') cho mọi response.

#### 🔴 TP · LOW · Header Content-Disposition/HTML: xuất HTML không chống XSS rõ ràng cho dữ liệu letterhead đọc tùy ý — `app/medicare/record/router.py:139`

CWE-79 · OWASP A05 · độ tin cậy 0.40 · nguồn: agent

**Phân tích:** Template được render bằng templates.get_template(...).render trực tiếp; cần đảm bảo autoescape bật cho môi trường này (không qua render()). Nếu tắt, các trường như symptoms/notes sẽ gây XSS.

**Đề xuất sửa:** Xác nhận Jinja2 autoescape bật cho .html; thêm header Content-Security-Policy và X-Content-Type-Options: nosniff cho response xuất.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /.

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health, cùng nguyên nhân thiếu middleware header.

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong code.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 43.3 s · 18 lần gọi LLM · 17 lần gọi công cụ · 99192 token vào / 6432 token ra · ≈ $0.1500 · chạm giới hạn: không</sub>
