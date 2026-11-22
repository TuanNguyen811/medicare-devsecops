<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `8855b63`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | claim_patient cho phép bác sĩ bất kỳ chiếm quyền phụ trách bệnh nhân (IDOR / bỏ qua policy) | `app/medicare/patient/service.py:127` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/claim:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.75 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · claim_patient cho phép bác sĩ bất kỳ chiếm quyền phụ trách bệnh nhân (IDOR / bỏ qua policy) — `app/medicare/patient/service.py:127`

CWE-639 · OWASP A01 · vi phạm R-02 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** service.claim_patient chỉ lấy bệnh nhân theo id rồi gán attending_doctor_id = doctor.id mà không gọi policy.can_view_patient hay kiểm tra cùng khoa. Route chỉ kiểm tra vai trò DOCTOR. Bác sĩ khoa khác chỉ cần POST /patients/{id}/claim với id đoán được để thành bác sĩ phụ trách. Khi đó _is_attending trả True, nên can_view_record, can_write_record và can_prescribe đều qua (R-01, R-02, R-03). Nút ở giao diện được ẩn nhưng server không chặn. Ngoài ra nếu department_id là None thì bị ghi đè bằng khoa của bác sĩ, và việc đổi người phụ trách không được ghi audit log.

**Kịch bản khai thác:** Bác sĩ khoa A gửi POST /patients/123/claim kèm CSRF token hợp lệ của chính mình. Bệnh nhân 123 thuộc khoa B. Bác sĩ này trở thành attending, rồi đọc bệnh án, tạo bệnh án mới và kê đơn cho bệnh nhân ngoài phạm vi của mình.

**Đề xuất sửa:** Trong router claim_patient, hoặc service.claim_patient, phải kiểm tra quyền ở phía server bằng một hàm policy mới, ví dụ policy.can_claim_patient(user, patient) trong app/medicare/policy.py. Hàm này chỉ cho phép bác sĩ cùng khoa với bệnh nhân (_same_department) và nên dùng cùng hàm cho cờ can_claim trong _detail_ctx. Không được gán attending khi bệnh nhân khác khoa; trả 403 hoặc 404. Không tự ghi đè department_id bằng khoa của bác sĩ. Ghi audit log cho mỗi lần đổi bác sĩ phụ trách. Bổ sung test cho trường hợp bác sĩ khác khoa bị từ chối.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy chỗ nào đặt X-Frame-Options hay frame-ancestors. Middleware trong main.py chỉ có Session, CatchAll và Metrics. Thiếu header chống clickjacking trên toàn app, không riêng PR này.

**Đề xuất sửa:** Thêm một middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trùng nguyên nhân với F1: không có header chống clickjacking nào trong app, kể cả trang /login.

**Đề xuất sửa:** Dùng middleware security headers chung trong app/medicare/main.py (X-Frame-Options DENY, frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo. Đây là giảm lớp phòng thủ XSS cho toàn app.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Cùng nguyên nhân: thiếu CSP trên toàn app.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/claim:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Cùng nguyên nhân: thiếu CSP, kể cả với route claim mới.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Cùng nguyên nhân: thiếu CSP trên toàn app.

**Đề xuất sửa:** Thêm CSP trong middleware chung ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Cùng nguyên nhân: thiếu X-Content-Type-Options trên toàn app.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Cùng nguyên nhân: thiếu X-Content-Type-Options, kể cả với /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có chỗ nào đặt X-Content-Type-Options trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 37.1 s · 16 lần gọi LLM · 15 lần gọi công cụ · 60252 token vào / 5508 token ra · ≈ $0.1083 · chạm giới hạn: không</sub>
