<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `8855b63`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | claim_patient cho phép bác sĩ bất kỳ chiếm quyền phụ trách bệnh nhân của khoa khác (IDOR/leo thang đặc quyền) | `app/medicare/patient/service.py:129` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/claim:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · claim_patient cho phép bác sĩ bất kỳ chiếm quyền phụ trách bệnh nhân của khoa khác (IDOR/leo thang đặc quyền) — `app/medicare/patient/service.py:129`

CWE-639 · OWASP A01 · vi phạm R-02 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** service.claim_patient chỉ kiểm tra bệnh nhân tồn tại rồi gán attending_doctor_id = doctor.id, không qua hàm policy.can_*. Vì "phụ trách" cấp quyền xem/sửa bệnh án và kê đơn (R-02, R-03), bác sĩ thuộc khoa khác tự cấp cho mình quyền truy cập lâm sàng của bất kỳ bệnh nhân nào chỉ bằng ID. Việc đổi người phụ trách cũng không ghi audit log, và khi department_id rỗng thì còn bị gán sang khoa của bác sĩ.

**Kịch bản khai thác:** Bác sĩ khoa A gửi POST /patients/<id bệnh nhân khoa B>/claim kèm CSRF token hợp lệ, trở thành bác sĩ phụ trách, rồi đọc/tạo bệnh án và kê đơn cho bệnh nhân đó.

**Đề xuất sửa:** Thêm hàm policy.can_claim_patient(user, patient) trong app/medicare/policy.py (docstring ghi R-02/R-03): chỉ cho bác sĩ cùng khoa (department_id cả hai khác rỗng và bằng nhau), hoặc theo quy trình do ADMIN duyệt. Gọi hàm này trong service.claim_patient (và dùng cho cờ can_claim trong _detail_ctx); nếu không đủ quyền trả NotFound (404, R-15). Không tự gán department_id từ bác sĩ. Ghi audit log mỗi lần đổi attending_doctor_id.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không có X-Frame-Options hay frame-ancestors nào; ứng dụng không đặt header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers dùng chung cho toàn app: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong repo (cùng nguyên nhân F1).

**Đề xuất sửa:** Thêm middleware security headers: X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware security headers.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/claim:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo; áp dụng cho cả response của route claim mới.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, không có header nào trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; middleware chung sẽ xử lý.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers áp dụng cho mọi route.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options: nosniff ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers, thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 35.8 s · 15 lần gọi LLM · 14 lần gọi công cụ · 73631 token vào / 5258 token ra · ≈ $0.1152 · chạm giới hạn: không</sub>
