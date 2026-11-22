<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `8855b63`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Bác sĩ bất kỳ có thể tự nhận phụ trách mọi bệnh nhân (IDOR, leo thang quyền) | `app/medicare/patient/service.py:129` | 0.90 |
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

#### 🔴 TP · HIGH · Bác sĩ bất kỳ có thể tự nhận phụ trách mọi bệnh nhân (IDOR, leo thang quyền) — `app/medicare/patient/service.py:129`

CWE-639 · OWASP A01 · vi phạm R-02 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** claim_patient chỉ kiểm tra vai trò DOCTOR, không gọi policy.can_* nào. Bác sĩ khoa khác có thể gán attending_doctor_id = mình cho bất kỳ bệnh nhân, từ đó được xem/tạo/sửa bệnh án và kê đơn (R-02, R-03). Cũng có thể chiếm bệnh nhân đang do bác sĩ khác phụ trách, và không ghi audit log.

**Kịch bản khai thác:** Bác sĩ khoa A gửi POST /patients/{id}/claim với id bệnh nhân khoa B (CSRF token lấy từ phiên của mình), trở thành bác sĩ phụ trách rồi đọc bệnh án và kê đơn.

**Đề xuất sửa:** Thêm hàm policy.can_claim_patient(user, patient) trong app/medicare/policy.py (chỉ cho bác sĩ cùng khoa, hoặc bệnh nhân chưa có bác sĩ phụ trách) và gọi nó trong service.claim_patient cũng như khi tính can_claim ở _detail_ctx. Nếu không đủ quyền thì trả NotFound (404, R-15). Ghi audit log mỗi lần đổi người phụ trách.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app chỉ thêm middleware CatchAllErrors, Session, Metrics; không có middleware đặt X-Frame-Options hay CSP frame-ancestors.

**Đề xuất sửa:** Thêm middleware security headers trong create_app (main.py): X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; không có middleware nào đặt header.

**Đề xuất sửa:** Thêm middleware security headers dùng chung trong main.py (X-Frame-Options DENY / frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP được đặt ở bất kỳ đâu trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self') qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/claim:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng; áp dụng cho mọi route kể cả route claim mới.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu header nosniff toàn ứng dụng.

**Đề xuất sửa:** Middleware security headers chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu nosniff ở /health do cùng nguyên nhân thiếu middleware; rủi ro thấp.

**Đề xuất sửa:** Middleware security headers chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response trong main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 56.9 s · 26 lần gọi LLM · 15 lần gọi công cụ · 115248 token vào / 9714 token ra · ≈ $0.1981 · chạm giới hạn: không</sub>
