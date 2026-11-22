<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `66d16bf`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Xuất CSV cho cả DOCTOR/NURSE và lộ CCCD/BHYT đầy đủ (vi phạm R-11, ma trận phân quyền) | `app/medicare/patient/router.py:98` | 0.90 |
| 🔴 TP | MEDIUM | agent | CSV export không trung hòa ô bắt đầu bằng =,+,-,@ (CSV/formula injection) | `app/medicare/common/csv_export.py:14` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Xuất CSV cho cả DOCTOR/NURSE và lộ CCCD/BHYT đầy đủ (vi phạm R-11, ma trận phân quyền) — `app/medicare/patient/router.py:98`

CWE-863 · OWASP A01 · vi phạm R-11 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /patients/export dùng staff_user (gồm DOCTOR, NURSE) trong khi ma trận chỉ cho ADMIN và RECEPTIONIST xuất. Dữ liệu xuất ghi p.national_id và p.insurance_number nguyên bản, không che, nên bác sĩ/y tá lấy được CCCD/BHYT đầy đủ.

**Kịch bản khai thác:** Y tá đăng nhập, gọi GET /patients/export và tải CSV chứa CCCD và mã BHYT đầy đủ của tối đa 5000 bệnh nhân trong phạm vi xem.

**Đề xuất sửa:** Đổi dependency của export_patients sang editor_user (require_roles(*EDITORS) = ADMIN, RECEPTIONIST). Áp dụng cùng cơ chế che định danh của R-11 cho CCCD/BHYT nếu vai trò không được xem đầy đủ.

#### 🔴 TP · MEDIUM · CSV export không trung hòa ô bắt đầu bằng =,+,-,@ (CSV/formula injection) — `app/medicare/common/csv_export.py:14`

CWE-1236 · OWASP A05 · vi phạm R-19 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** csv_response chỉ chuyển giá trị sang str rồi ghi; các trường do người dùng nhập (họ tên, địa chỉ) không bị trung hòa ký tự đầu =, +, -, @, tab, xuống dòng.

**Kịch bản khai thác:** Lễ tân/bệnh nhân nhập địa chỉ '=HYPERLINK(...)'; khi nhân viên mở CSV bằng Excel, công thức chạy và có thể rò rỉ dữ liệu.

**Đề xuất sửa:** Trong csv_response, với mỗi ô chuỗi bắt đầu bằng =, +, -, @, tab hoặc \r/\n thì thêm tiền tố dấu nháy đơn (') trước khi ghi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay frame-ancestors; ứng dụng không đặt header chống clickjacking.

**Đề xuất sửa:** Thêm middleware toàn cục trong app factory đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong code; trang /login dễ bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong code.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong code.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong code.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong code.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong code.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong code.

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong code.

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong code.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 37.6 s · 17 lần gọi LLM · 16 lần gọi công cụ · 97656 token vào / 5499 token ra · ≈ $0.1277 · chạm giới hạn: không</sub>
