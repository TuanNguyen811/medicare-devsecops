<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `7c3b3e1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | IDOR: y tá xem danh sách bệnh nhân của khoa bất kỳ qua department_id | `app/medicare/patient/router.py:99` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: y tá xem danh sách bệnh nhân của khoa bất kỳ qua department_id — `app/medicare/patient/router.py:99`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /ward/patients nhận department_id từ query và dùng trực tiếp, không so khớp với user.department_id và không gọi policy.can_view_patient. Theo ma trận phân quyền, y tá chỉ xem bệnh nhân cùng khoa, nên có thể liệt kê toàn bộ bệnh nhân khoa khác (họ tên, ngày sinh, CCCD/BHYT che, BS phụ trách, ngày khám). Dropdown trong ward.html còn mời chọn khoa khác. Cũng không tuân R-15.

**Kịch bản khai thác:** Y tá khoa NOI gọi GET /ward/patients?department_id=2 và nhận danh sách bệnh nhân khoa NGOAI; lặp qua các id khoa để thu thập toàn bộ bệnh nhân của bệnh viện.

**Đề xuất sửa:** Trong ward_patients (app/medicare/patient/router.py) không dùng department_id của client để mở rộng phạm vi: bỏ tham số hoặc chỉ chấp nhận khi bằng user.department_id (nếu khác thì trả NotFound/404). Đồng thời lọc từng bệnh nhân bằng policy.can_view_patient(user, p) trước khi render. Bỏ dropdown chọn khoa khác trong ward.html.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt header bảo mật nào (search toàn repo không thấy X-Frame-Options, nosniff hay CSP); middleware chỉ có error, session, metrics.

**Đề xuất sửa:** Thêm một middleware security headers trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login không chống clickjacking vì không có middleware đặt header bảo mật.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py): X-Frame-Options DENY / frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff, không có header bảo mật nào được đặt.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health cũng thiếu nosniff vì không có middleware header.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app (main.py).

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware chung ở main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware chung ở main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware chung ở main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware chung ở main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 62.5 s · 28 lần gọi LLM · 17 lần gọi công cụ · 174773 token vào / 10521 token ra · ≈ $0.1859 · chạm giới hạn: không</sub>
