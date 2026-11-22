<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `66d16bf`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Export cho phép DOCTOR/NURSE và xuất CCCD, BHYT đầy đủ không che | `app/medicare/patient/router.py:98` | 0.90 |
| 🔴 TP | MEDIUM | agent | Xuất CSV không trung hòa ô bắt đầu bằng =,+,-,@ (CSV/formula injection) | `app/medicare/common/csv_export.py:14` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.55 |

### Chi tiết

#### 🔴 TP · HIGH · Export cho phép DOCTOR/NURSE và xuất CCCD, BHYT đầy đủ không che — `app/medicare/patient/router.py:98`

CWE-285 · OWASP A01 · vi phạm R-11 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** export_patients dùng staff_user (gồm DOCTOR, NURSE) trong khi ma trận chỉ cho ADMIN và RECEPTIONIST xuất. Đồng thời p.national_id và p.insurance_number được ghi nguyên bản, bỏ qua _identifiers/policy.can_view_identifiers, nên bác sĩ/y tá lấy được CCCD, BHYT đầy đủ của mọi bệnh nhân trong phạm vi khoa. Vi phạm R-11 và R-19.

**Kịch bản khai thác:** Một y tá đăng nhập, gọi GET /patients/export và nhận CSV chứa CCCD và mã BHYT đầy đủ của mọi bệnh nhân cùng khoa, dữ liệu mà giao diện thường che.

**Đề xuất sửa:** Đổi dependency của export_patients sang require_roles(*EDITORS) (ADMIN, RECEPTIONIST) hoặc một policy.can_export_patients mới. Với mỗi bệnh nhân dùng _identifiers(user, p) (policy.can_view_identifiers) thay vì ghi trực tiếp national_id và insurance_number. Bổ sung test DOCTOR/NURSE nhận 403.

#### 🔴 TP · MEDIUM · Xuất CSV không trung hòa ô bắt đầu bằng =,+,-,@ (CSV/formula injection) — `app/medicare/common/csv_export.py:14`

CWE-1236 · OWASP A05 · vi phạm R-19 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** csv_response chỉ chuyển giá trị sang str rồi ghi, không trung hòa ô bắt đầu bằng =, +, -, @, tab, xuống dòng. Các trường full_name, address do người dùng nhập có thể chứa công thức. Vi phạm R-19.

**Kịch bản khai thác:** Lễ tân/bên ngoài nhập họ tên hoặc địa chỉ là =HYPERLINK(...) hoặc =cmd|...; khi admin mở file CSV trong Excel, công thức được thực thi, có thể rò rỉ dữ liệu hoặc chạy lệnh.

**Đề xuất sửa:** Trong csv_export.csv_response, trước khi ghi mỗi ô chuỗi, nếu bắt đầu bằng =, +, -, @, tab hoặc \r/\n thì thêm tiền tố dấu nháy đơn '. Áp dụng cho mọi ô (kể cả họ tên, địa chỉ, tên khoa, tên bác sĩ) và thêm test.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP quan sát động thấy phản hồi thiếu X-Frame-Options / frame-ancestors. Trong phạm vi xem được không có middleware đặt header bảo mật nên không có bằng chứng để bác bỏ.

**Đề xuất sửa:** Thêm middleware dùng chung (app factory) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; trang đăng nhập đặc biệt dễ bị framing.

**Đề xuất sửa:** Dùng cùng middleware security headers toàn cục: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /.

**Đề xuất sửa:** Thêm nosniff trong middleware security headers toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; rủi ro thấp nhưng cùng nguyên nhân gốc.

**Đề xuất sửa:** Thêm nosniff trong middleware security headers toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Phản hồi /login thiếu X-Content-Type-Options: nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu header Content-Security-Policy trên phản hồi; không thấy middleware đặt CSP.

**Đề xuất sửa:** Đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Sửa một lần bằng middleware CSP toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Sửa một lần bằng middleware CSP toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Sửa một lần bằng middleware CSP toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Sửa một lần bằng middleware CSP toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 48.2 s · 3 lần gọi LLM · 13 lần gọi công cụ · 54780 token vào / 8397 token ra · ≈ $0.2033 · chạm giới hạn: không</sub>
