<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `66d16bf`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Xuất CSV cho phép DOCTOR/NURSE và lộ CCCD, BHYT đầy đủ (vi phạm ma trận quyền, R-11, R-19) | `app/medicare/patient/router.py:98` | 0.90 |
| 🔴 TP | MEDIUM | agent | CSV injection: ô bắt đầu bằng = + - @ không được trung hòa (R-19) | `app/medicare/common/csv_export.py:14` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Xuất CSV cho phép DOCTOR/NURSE và lộ CCCD, BHYT đầy đủ (vi phạm ma trận quyền, R-11, R-19) — `app/medicare/patient/router.py:98`

CWE-285 · OWASP A01 · vi phạm R-11 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /patients/export dùng staff_user (gồm DOCTOR, NURSE) trong khi ma trận chỉ cho ADMIN và RECEPTIONIST xuất dữ liệu. Ngoài ra p.national_id và p.insurance_number được xuất nguyên văn, không che (mask) theo vai trò, nên bác sĩ và y tá lấy được CCCD/BHYT đầy đủ của tới 5000 bệnh nhân trong phạm vi của họ.

**Đề xuất sửa:** Trong app/medicare/patient/router.py, hàm export_patients: đổi Depends(staff_user) thành Depends(editor_user) (chỉ RECEPTIONIST, ADMIN). Đồng thời xử lý CCCD/BHYT qua cùng cơ chế che mask/policy dùng ở trang chi tiết (medicare.validators.mask và _identifiers) thay vì xuất p.national_id, p.insurance_number nguyên văn.

#### 🔴 TP · MEDIUM · CSV injection: ô bắt đầu bằng = + - @ không được trung hòa (R-19) — `app/medicare/common/csv_export.py:14`

CWE-1236 · OWASP A05 · vi phạm R-19 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** csv_response ghi str(value) trực tiếp. Họ tên, địa chỉ do lễ tân nhập (hoặc dữ liệu nhập từ bên ngoài) có thể bắt đầu bằng =, +, -, @, tab; khi quản trị mở file trong Excel, công thức sẽ được thực thi. Ngoài ra filename đưa vào header Content-Disposition không được kiểm tra (hiện là hằng nên rủi ro thấp).

**Đề xuất sửa:** Trong csv_response (app/medicare/common/csv_export.py), thêm bước trung hòa cho mỗi ô chuỗi: nếu bắt đầu bằng =, +, -, @, tab hoặc \r/\n thì thêm tiền tố dấu nháy đơn ('). Áp dụng cho mọi ô, kể cả header. Bổ sung test cho trường hợp này.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay frame-ancestors ở bất kỳ đâu trong repo, và main.py chỉ có middleware lỗi, session, metrics. Trang bị thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm một middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Như F1: trang /login thiếu header chống clickjacking, ứng dụng không đặt header bảo mật nào.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong app/medicare/main.py (X-Frame-Options: DENY, CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options nào trong code.

**Đề xuất sửa:** Middleware chung trong app/medicare/main.py đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options nào trong code, kể cả endpoint /health.

**Đề xuất sửa:** Middleware chung trong app/medicare/main.py đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options nào trong code.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung trong app/medicare/main.py đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 38.1 s · 18 lần gọi LLM · 17 lần gọi công cụ · 102435 token vào / 5934 token ra · ≈ $0.0982 · chạm giới hạn: không</sub>
