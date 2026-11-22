<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `8855b63`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | claim_patient cho phép bất kỳ bác sĩ nào chiếm quyền phụ trách bệnh nhân của khoa khác (IDOR / broken access control) | `app/medicare/patient/service.py:127` | 0.90 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.55 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/claim:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.55 |

### Chi tiết

#### 🔴 TP · HIGH · claim_patient cho phép bất kỳ bác sĩ nào chiếm quyền phụ trách bệnh nhân của khoa khác (IDOR / broken access control) — `app/medicare/patient/service.py:127`

CWE-639 · OWASP A01 · vi phạm R-02 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Hàm service.claim_patient dùng db.get(Patient, patient_id) trực tiếp, không gọi policy.can_view_patient hay kiểm tra cùng khoa. Route chỉ yêu cầu vai trò DOCTOR. Vì vậy mọi bác sĩ có thể đổi attending_doctor_id của bệnh nhân bất kỳ, kể cả khoa khác hoặc bệnh nhân đã có bác sĩ phụ trách. Sau đó họ trở thành "bác sĩ phụ trách", nên được xem, tạo, sửa bệnh án và kê đơn (R-02, R-03), và thấy hồ sơ bệnh nhân. Ma trận phân quyền không cho bác sĩ tự gán phụ trách. Ngoài ra, endpoint trả 303 khi bệnh nhân tồn tại và 404 khi không, nên lộ sự tồn tại của đối tượng mà người đó không có quyền xem (R-15). Nếu patient.department_id là None thì bị gán theo khoa của bác sĩ. Hành động đổi quyền phụ trách cũng không ghi audit log.

**Kịch bản khai thác:** Bác sĩ A khoa Ngoại gửi POST /patients/123/claim (kèm CSRF token hợp lệ) cho bệnh nhân khoa Nội. Hệ thống đặt attending_doctor_id = A. A giờ xem và sửa được bệnh án, kê đơn và xem dữ liệu lâm sàng của bệnh nhân đó, dù không có quyền. A cũng có thể duyệt id để dò xem bệnh nhân nào tồn tại.

**Đề xuất sửa:** Trong service.claim_patient, tải bệnh nhân qua get_patient_for hoặc kiểm tra policy.can_view_patient(doctor, patient). Nếu không có quyền thì raise NotFound (R-15). Thêm hàm policy.can_claim_patient trong app/medicare/policy.py, chỉ cho phép khi bác sĩ cùng khoa với bệnh nhân (cả hai department_id khác rỗng và bằng nhau), và dùng hàm này cả cho cờ can_claim trong _detail_ctx. Không tự gán department_id của bệnh nhân bằng khoa của bác sĩ. Nếu bệnh nhân đã có bác sĩ phụ trách khác thì cần quy trình bàn giao có kiểm soát hoặc do ADMIN/lễ tân thực hiện. Ghi audit log mỗi lần đổi quyền phụ trách. Sửa test test_doctor_takes_over_patient_of_department và thêm test bác sĩ khác khoa nhận 404.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP quan sát thấy phản hồi thiếu X-Frame-Options hoặc frame-ancestors. Đây là lỗi cấu hình toàn cục, không nằm trong code của PR, và tôi không có bằng chứng code nào cho thấy đã có middleware đặt header. Hệ thống có thao tác thay đổi dữ liệu y tế nên clickjacking là rủi ro thật, dù CSRF token giảm nhẹ.

**Đề xuất sửa:** Thêm middleware bảo mật dùng chung trong app factory để đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Phản hồi GET / thiếu X-Content-Type-Options: nosniff. Lỗi cấu hình toàn cục, rủi ro thấp.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Phản hồi GET /health thiếu X-Content-Type-Options: nosniff. Cùng nguyên nhân gốc, rủi ro thấp vì endpoint trả dữ liệu đơn giản.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật toàn cục.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking. Cùng nguyên nhân gốc với F1 (không có middleware header bảo mật toàn cục). Trang đăng nhập có thể bị nhúng vào iframe để lừa người dùng.

**Đề xuất sửa:** Dùng chung middleware header bảo mật toàn cục: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Phản hồi /login thiếu X-Content-Type-Options: nosniff. Đây là lỗi cấu hình toàn cục, tôi không có bằng chứng code cho thấy header đã được đặt.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu Content-Security-Policy trên phản hồi của POST /appointments. Lỗi cấu hình toàn cục, mất lớp phòng thủ chiều sâu chống XSS.

**Đề xuất sửa:** Đặt CSP chặt (default-src 'self', frame-ancestors 'none') trong middleware header bảo mật toàn cục, áp dụng cho cả phản hồi redirect và lỗi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP trên phản hồi của POST /patients. Cùng nguyên nhân gốc là chưa có header bảo mật toàn cục.

**Đề xuất sửa:** Đặt CSP trong middleware header bảo mật toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/claim:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP trên phản hồi của POST /patients/{patient_id}/claim (route mới của PR). Cùng nguyên nhân gốc, cần sửa toàn cục chứ không riêng route này.

**Đề xuất sửa:** Đặt CSP trong middleware header bảo mật toàn cục để mọi route, gồm route claim, đều có header.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP trên phản hồi của POST /patients/{patient_id}/edit. Cùng nguyên nhân gốc là chưa có header bảo mật toàn cục.

**Đề xuất sửa:** Đặt CSP trong middleware header bảo mật toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 37.3 s · 12 lần gọi LLM · 11 lần gọi công cụ · 53965 token vào / 5667 token ra · ≈ $0.1700 · chạm giới hạn: không</sub>
