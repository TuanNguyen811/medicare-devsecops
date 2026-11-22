<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `7c3b3e1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | IDOR: y tá xem danh sách bệnh nhân của khoa bất kỳ qua tham số department_id | `app/medicare/patient/router.py:100` | 0.93 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · IDOR: y tá xem danh sách bệnh nhân của khoa bất kỳ qua tham số department_id — `app/medicare/patient/router.py:100`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.93 · nguồn: agent

**Phân tích:** Route /ward/patients nhận department_id từ client và dùng trực tiếp, không kiểm tra trùng với user.department_id và không gọi policy.can_view_patient cho từng bệnh nhân. Ma trận quyền: y tá chỉ xem bệnh nhân cùng khoa. Y tá có thể liệt kê bệnh nhân (mã, họ tên, ngày sinh, giới tính, CCCD/BHYT che, bác sĩ, ngày khám gần nhất) của mọi khoa. Test chỉ kiểm tra khoa mặc định nên không phát hiện.

**Kịch bản khai thác:** Y tá khoa Nội gọi GET /ward/patients?department_id=2 và nhận danh sách bệnh nhân khoa Ngoại, ngoài phạm vi được phép.

**Đề xuất sửa:** Trong router.ward_patients bỏ việc tin department_id từ client: luôn dùng user.department_id (nếu None thì trả danh sách rỗng), hoặc nếu giữ tham số thì từ chối (404) khi khác user.department_id. Có thể lọc từng bệnh nhân bằng policy.can_view_patient(user, p) trước khi hiển thị. Bỏ danh sách chọn khoa trong ward.html và thêm test cho department_id của khoa khác.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options, CSP frame-ancestors hay middleware đặt security header nào, nên các response thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware (hoặc cấu hình reverse proxy) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có security header nào trong repo (đã tìm); trang /login thiếu header chống clickjacking.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY / CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu, /health cũng thiếu.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 33.2 s · 15 lần gọi LLM · 14 lần gọi công cụ · 90552 token vào / 4878 token ra · ≈ $0.1247 · chạm giới hạn: không</sub>
