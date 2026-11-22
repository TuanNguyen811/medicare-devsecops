<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `7c3b3e1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | IDOR: y tá xem được bệnh nhân của khoa khác qua tham số department_id | `app/medicare/patient/router.py:99` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: y tá xem được bệnh nhân của khoa khác qua tham số department_id — `app/medicare/patient/router.py:99`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /ward/patients chỉ kiểm tra vai trò NURSE, rồi dùng department_id từ query (ưu tiên hơn user.department_id) để lấy toàn bộ bệnh nhân của khoa bất kỳ. Không gọi policy.can_view_patient (với NURSE chỉ cho phép cùng khoa theo _clinical_scope, R-01/R-12). Danh sách trả về họ tên, ngày sinh, CCCD/BHYT (đã mask), bác sĩ phụ trách và ngày khám gần nhất của bệnh nhân ngoài phạm vi. Form còn liệt kê mọi khoa. Test chỉ kiểm tra trường hợp mặc định.

**Kịch bản khai thác:** Y tá khoa NOI gọi GET /ward/patients?department_id=2 (khoa NGOAI) và nhận danh sách tối đa 200 bệnh nhân khoa khác kèm thông tin cá nhân và ngày khám; có thể duyệt lần lượt mọi department_id.

**Đề xuất sửa:** Trong ward_patients (router.py) không tin department_id từ client: luôn dùng user.department_id của y tá, hoặc nếu giữ tham số thì chỉ chấp nhận khi bằng user.department_id (ngược lại trả 403/NotFound). Lọc từng bệnh nhân bằng policy.can_view_patient(user, p) trước khi đưa vào rows. Bỏ danh sách tất cả các khoa trong ward.html. Thêm test cho department_id khác khoa.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app không có middleware nào thêm X-Frame-Options hay CSP frame-ancestors; tìm kiếm trong repo không thấy header bảo mật nào. Trang có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm một middleware trong create_app (main.py) đặt X-Frame-Options: DENY, X-Content-Type-Options: nosniff và Content-Security-Policy (có frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking vì ứng dụng không đặt header bảo mật nào.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong main.py (X-Frame-Options DENY / CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware chung ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header nosniff trên mọi response.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung ở main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** /health cũng thiếu nosniff do không có middleware header; rủi ro thấp.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung ở main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 63.0 s · 29 lần gọi LLM · 18 lần gọi công cụ · 128841 token vào / 11018 token ra · ≈ $0.2180 · chạm giới hạn: không</sub>
