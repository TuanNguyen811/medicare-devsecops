<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `66d16bf`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Export CSV cho DOCTOR/NURSE, lộ CCCD/BHYT không che (vi phạm R-11, R-19, ma trận quyền) | `app/medicare/patient/router.py:98` | 0.90 |
| 🔴 TP | MEDIUM | agent | CSV injection: csv_response không trung hòa ô bắt đầu bằng = + - @ | `app/medicare/common/csv_export.py:14` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Export CSV cho DOCTOR/NURSE, lộ CCCD/BHYT không che (vi phạm R-11, R-19, ma trận quyền) — `app/medicare/patient/router.py:98`

CWE-285 · OWASP A01 · vi phạm R-19 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** /patients/export dùng staff_user (gồm DOCTOR, NURSE) trong khi ma trận chỉ cho ADMIN và RECEPTIONIST xuất. Dòng xuất ghi p.national_id và p.insurance_number nguyên văn, không qua mask, nên bác sĩ/y tá lấy được CCCD/BHYT đầy đủ, trái R-11.

**Kịch bản khai thác:** Y tá đăng nhập, gọi GET /patients/export và nhận CSV chứa CCCD, BHYT đầy đủ của mọi bệnh nhân cùng khoa (tối đa 5000).

**Đề xuất sửa:** Trong export_patients dùng editor_user (ADMIN, RECEPTIONIST) thay vì staff_user. Nếu mở rộng vai trò, áp dụng validators.mask cho national_id và insurance_number theo vai trò như trang chi tiết (R-11).

#### 🔴 TP · MEDIUM · CSV injection: csv_response không trung hòa ô bắt đầu bằng = + - @ — `app/medicare/common/csv_export.py:14`

CWE-1236 · OWASP A05 · vi phạm R-19 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** csv_response chỉ chuyển str(value) rồi ghi, không xử lý ký tự đầu công thức. Các trường như họ tên, địa chỉ do người dùng nhập có thể là công thức Excel.

**Kịch bản khai thác:** Lễ tân/bệnh nhân nhập địa chỉ '=HYPERLINK(...)'. Khi admin mở CSV bằng Excel, công thức thực thi và rò rỉ dữ liệu.

**Đề xuất sửa:** Trong csv_export.py thêm hàm trung hòa: nếu chuỗi bắt đầu bằng =, +, -, @, tab hoặc CR/LF thì thêm tiền tố dấu nháy đơn; áp dụng cho mọi ô trước writerow. Cũng làm sạch filename.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** create_app không có middleware đặt X-Frame-Options/CSP frame-ancestors; tìm trong code không thấy header bảo mật nào.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong toàn ứng dụng (create_app chỉ có Session/Metrics/CatchAll middleware); trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Thêm middleware đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP (default-src 'self', frame-ancestors 'none') qua middleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options toàn ứng dụng.

**Đề xuất sửa:** Thêm header nosniff qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health do không có middleware header.

**Đề xuất sửa:** Thêm header nosniff qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware security headers trong main.py đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 42.0 s · 19 lần gọi LLM · 18 lần gọi công cụ · 100809 token vào / 5888 token ra · ≈ $0.0984 · chạm giới hạn: không</sub>
