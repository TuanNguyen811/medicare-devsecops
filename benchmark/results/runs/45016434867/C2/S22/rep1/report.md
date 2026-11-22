<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `66d16bf`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Export CSV cho phép DOCTOR/NURSE xuất CCCD, BHYT đầy đủ (không che) | `app/medicare/patient/router.py:102` | 0.90 |
| 🔴 TP | MEDIUM | agent | CSV formula injection trong csv_response | `app/medicare/common/csv_export.py:15` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Export CSV cho phép DOCTOR/NURSE xuất CCCD, BHYT đầy đủ (không che) — `app/medicare/patient/router.py:102`

CWE-862 · OWASP A01 · vi phạm R-19 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Route /patients/export dùng staff_user (gồm DOCTOR, NURSE) trong khi ma trận chỉ cho ADMIN và RECEPTIONIST xuất danh sách. Dữ liệu xuất ghi p.national_id và p.insurance_number thô, không qua mask, vi phạm R-11/R-19.

**Kịch bản khai thác:** Bác sĩ hoặc y tá gọi GET /patients/export và tải CCCD, mã BHYT đầy đủ của tất cả bệnh nhân trong phạm vi khoa (tối đa 5000 dòng).

**Đề xuất sửa:** Đổi dependency của export_patients sang editor_user (require_roles(*EDITORS), tức ADMIN và RECEPTIONIST). Nếu sau này mở rộng vai trò, áp dụng validators.mask cho national_id và insurance_number như R-11.

#### 🔴 TP · MEDIUM · CSV formula injection trong csv_response — `app/medicare/common/csv_export.py:15`

CWE-1236 · OWASP A05 · vi phạm R-19 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Các giá trị chuỗi (full_name, address, ...) do người dùng nhập được ghi trực tiếp vào CSV mà không trung hòa ô bắt đầu bằng =, +, -, @, tab hoặc xuống dòng, vi phạm R-19.

**Kịch bản khai thác:** Người dùng đăng ký bệnh nhân với địa chỉ '=HYPERLINK(...)'. Khi lễ tân mở CSV trong Excel, công thức chạy và có thể rò rỉ dữ liệu.

**Đề xuất sửa:** Trong csv_export.csv_response, với mỗi ô chuỗi bắt đầu bằng =, +, -, @, tab hoặc CR/LF thì thêm tiền tố dấu nháy đơn (') trước khi writerow. Thêm test cho trường hợp này.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không có chỗ nào đặt X-Frame-Options hoặc frame-ancestors, nên ZAP đúng.

**Đề xuất sửa:** Thêm middleware chung trong app chính đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login dễ bị framing.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware chung đặt Content-Security-Policy chặt.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 37.7 s · 20 lần gọi LLM · 19 lần gọi công cụ · 102811 token vào / 5650 token ra · ≈ $0.1354 · chạm giới hạn: không</sub>
