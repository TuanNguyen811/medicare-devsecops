<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `7c3b3e1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | IDOR: y tá xem được danh sách bệnh nhân của khoa khác qua tham số department_id | `app/medicare/patient/router.py:100` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.55 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: y tá xem được danh sách bệnh nhân của khoa khác qua tham số department_id — `app/medicare/patient/router.py:100`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /ward/patients nhận department_id từ query và dùng trực tiếp (department_id or user.department_id) để truy vấn bệnh nhân. Không có kiểm tra user.department_id == department_id, cũng không đi qua policy.can_view_patient. Theo ma trận phân quyền, y tá chỉ xem bệnh nhân cùng khoa. Y tá có thể liệt kê tên, ngày sinh, CCCD/BHYT (đã che), bác sĩ phụ trách và ngày khám của bệnh nhân mọi khoa. Dropdown còn liệt kê toàn bộ khoa. Test chỉ kiểm tra mặc định, không kiểm tra truy cập chéo khoa.

**Kịch bản khai thác:** Y tá khoa Nội gọi GET /ward/patients?department_id=2 (khoa Ngoại) và nhận danh sách bệnh nhân khoa Ngoại; có thể lặp qua mọi id để thu thập dữ liệu bệnh nhân toàn viện.

**Đề xuất sửa:** Trong router.py, hàm ward_patients: bỏ việc tin department_id từ client. Dùng user.department_id làm phạm vi duy nhất, hoặc nếu giữ tham số thì chỉ chấp nhận khi bằng user.department_id, ngược lại trả NotFound (R-15). Tốt nhất lọc từng bệnh nhân bằng policy.can_view_patient(user, p) hoặc dùng _scope_filter(user) trong service.ward_patients. Ẩn dropdown các khoa khác trong ward.html (chỉ khoa của y tá). Thêm test y tá truy cập department_id khoa khác phải bị từ chối/404.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP báo thiếu X-Frame-Options/frame-ancestors. Không thấy middleware đặt header bảo mật trong mã đã xem; template cũng không có cơ chế thay thế. Cần thêm header toàn cục.

**Đề xuất sửa:** Thêm middleware toàn cục (app factory) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking; trang đăng nhập là mục tiêu clickjacking. Không thấy header được đặt trong mã đã xem.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY / CSP frame-ancestors 'none', áp dụng cả /login.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Chưa có CSP; base.html nạp script/style từ cdn.jsdelivr.net và có style inline, nên cần CSP allowlist rõ ràng.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware toàn cục (default-src 'self', cho phép cdn.jsdelivr.net cho script/style/font, frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân thiếu CSP toàn cục như F6.

**Đề xuất sửa:** Giải quyết cùng F6 bằng middleware CSP toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân thiếu CSP toàn cục như F6.

**Đề xuất sửa:** Giải quyết cùng F6 bằng middleware CSP toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Cùng nguyên nhân thiếu CSP toàn cục như F6.

**Đề xuất sửa:** Giải quyết cùng F6 bằng middleware CSP toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên GET /; không thấy header được đặt.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu nosniff trên /health; rủi ro rất thấp nhưng được sửa cùng middleware toàn cục.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff, áp dụng cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên /login; sửa đơn giản bằng middleware. Rủi ro thực tế thấp.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 32.3 s · 12 lần gọi LLM · 11 lần gọi công cụ · 55493 token vào / 4801 token ra · ≈ $0.1620 · chạm giới hạn: không</sub>
