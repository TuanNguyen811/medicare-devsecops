<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `7c3b3e1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | IDOR: y tá xem danh sách bệnh nhân của khoa khác qua department_id | `app/medicare/patient/router.py:100` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: y tá xem danh sách bệnh nhân của khoa khác qua department_id — `app/medicare/patient/router.py:100`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** Route /ward/patients nhận department_id từ query và dùng trực tiếp (department_id or user.department_id) mà không kiểm tra khoa đó có phải khoa của y tá không và không gọi policy.can_view_patient. Theo ma trận, y tá chỉ xem bệnh nhân cùng khoa. Danh sách trả về tên, ngày sinh, giới tính, CCCD/BHYT (che), bác sĩ phụ trách, ngày khám gần nhất của mọi bệnh nhân khoa bất kỳ. Dropdown còn liệt kê mọi khoa nên dễ khai thác. Test chỉ kiểm tra trường hợp mặc định.

**Kịch bản khai thác:** Y tá khoa NOI gọi GET /ward/patients?department_id=<id khoa NGOAI> và nhận toàn bộ bệnh nhân (tối đa 200) của khoa khác.

**Đề xuất sửa:** Bỏ tham số department_id hoặc ép dùng user.department_id của y tá (nếu rỗng thì trả danh sách rỗng). Ngoài ra lọc từng bệnh nhân bằng policy.can_view_patient(user, p) trong ward_patients của router. Không liệt kê mọi khoa trong dropdown cho y tá. Thêm test y tá truyền department_id khoa khác phải không thấy dữ liệu (hoặc 404 theo R-15).

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay frame-ancestors; ứng dụng không đặt header chống clickjacking.

**Đề xuất sửa:** Thêm middleware (hoặc cấu hình reverse proxy) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng chung middleware đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo; /health cũng thiếu header.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options hay CSP ở bất kỳ đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff và Content-Security-Policy chặt.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục cho mọi response, kể cả redirect và lỗi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 35.0 s · 17 lần gọi LLM · 16 lần gọi công cụ · 88928 token vào / 5015 token ra · ≈ $0.0876 · chạm giới hạn: không</sub>
