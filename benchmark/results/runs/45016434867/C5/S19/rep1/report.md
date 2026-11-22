<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `7c3b3e1`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Y tá xem được danh sách bệnh nhân của khoa khác qua department_id (IDOR) | `app/medicare/patient/router.py:99` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Y tá xem được danh sách bệnh nhân của khoa khác qua department_id (IDOR) — `app/medicare/patient/router.py:99`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /ward/patients nhận department_id từ query và dùng trực tiếp, không kiểm tra bằng policy.can_view_patient. Y tá chỉ được xem bệnh nhân cùng khoa; ở đây còn trả về CCCD/BHYT (che), tên, ngày sinh, BS phụ trách và ngày khám của bệnh nhân khoa khác. Test cũng chỉ kiểm tra khoa mặc định.

**Kịch bản khai thác:** Y tá khoa NOI gọi GET /ward/patients?department_id=2 và liệt kê bệnh nhân khoa NGOAI, hoặc duyệt lần lượt các id.

**Đề xuất sửa:** Trong router.ward_patients bỏ việc tin department_id của client: chỉ dùng user.department_id (và không trả gì nếu rỗng), hoặc lọc từng bệnh nhân qua policy.can_view_patient(user, p). Bỏ dropdown chọn khoa khỏi ward.html (hoặc chỉ liệt kê khoa của y tá). Thêm test y tá yêu cầu department_id khoa khác phải không thấy dữ liệu.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay frame-ancestors ở đâu trong repo, nên ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware trong app chính đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng cùng middleware security headers: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none'), điều chỉnh cho CDN Bootstrap đang dùng.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP qua middleware chung cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options.

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options, kể cả cho /health.

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 33.2 s · 14 lần gọi LLM · 13 lần gọi công cụ · 82626 token vào / 4611 token ra · ≈ $0.1149 · chạm giới hạn: không</sub>
