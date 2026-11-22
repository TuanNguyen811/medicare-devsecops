<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `8855b63`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | claim_patient cho phép bác sĩ bất kỳ chiếm quyền phụ trách mọi bệnh nhân (thiếu kiểm tra policy) | `app/medicare/patient/service.py:127` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/claim:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · claim_patient cho phép bác sĩ bất kỳ chiếm quyền phụ trách mọi bệnh nhân (thiếu kiểm tra policy) — `app/medicare/patient/service.py:127`

CWE-639 · OWASP A01 · vi phạm R-02 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route POST /patients/{patient_id}/claim chỉ yêu cầu role DOCTOR, còn service.claim_patient lấy bệnh nhân bằng db.get rồi gán attending_doctor_id = doctor.id mà không gọi policy.can_* nào (không kiểm tra cùng khoa hay quyền xem). Vì R-02/R-03 cho "phụ trách" quyền tạo/sửa bệnh án và kê đơn, bác sĩ khoa khác tự gán mình thành bác sĩ phụ trách và có quyền lâm sàng trên bệnh nhân bất kỳ. Ngoài ra bệnh nhân không tồn tại và không có quyền lại phân biệt được (vi phạm R-15), và không có audit log cho việc đổi quyền phụ trách. Cũng ghi đè bác sĩ phụ trách hiện tại mà không cần đồng ý.

**Kịch bản khai thác:** Bác sĩ khoa A gửi POST /patients/123/claim (kèm CSRF token hợp lệ) cho bệnh nhân khoa B; trở thành attending_doctor, rồi đọc/tạo bệnh án và kê đơn cho bệnh nhân đó.

**Đề xuất sửa:** Trong service.claim_patient (hoặc router.claim_patient) thêm hàm policy.can_claim_patient(user, patient) trong app/medicare/policy.py: chỉ cho phép khi bác sĩ cùng khoa với bệnh nhân (department_id khác rỗng và bằng nhau) hoặc bệnh nhân chưa có bác sĩ phụ trách trong khoa của bác sĩ. Nếu không đạt, trả NotFound (404) giống bệnh nhân không tồn tại (R-15). Ghi audit log việc đổi attending_doctor_id. Cập nhật can_claim ở _detail_ctx dùng cùng hàm policy và thêm test bác sĩ khác khoa bị 404.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors (main.py chỉ có Session, CatchAll, Metrics). Cần thêm security headers middleware.

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login không có X-Frame-Options/frame-ancestors vì không có middleware đặt header; có thể bị clickjacking.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py với X-Frame-Options: DENY.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy được đặt ở bất kỳ đâu trong ứng dụng.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/claim:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục, áp dụng cả cho route claim mới.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, không có middleware đặt header.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py (nosniff).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân thiếu middleware, mức rủi ro thấp.

**Đề xuất sửa:** Thêm middleware security headers toàn cục trong app/medicare/main.py (nosniff).

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options: nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 34.3 s · 15 lần gọi LLM · 14 lần gọi công cụ · 76320 token vào / 5313 token ra · ≈ $0.0858 · chạm giới hạn: không</sub>
