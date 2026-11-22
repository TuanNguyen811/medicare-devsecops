<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f6471ae`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | adjust_coverage cho phép client gửi tỷ lệ BHYT, vi phạm tính toán ở server | `app/medicare/billing/router.py:115` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · adjust_coverage cho phép client gửi tỷ lệ BHYT, vi phạm tính toán ở server — `app/medicare/billing/router.py:115`

CWE-639 · OWASP A06 · vi phạm R-04 · độ tin cậy 0.85 · nguồn: agent

**Phân tích:** Endpoint POST /invoices/{invoice_id}/coverage nhận coverage_rate từ form và ghi thẳng vào invoice.coverage_rate, insurance_amount, patient_amount. R-04 và R-17 yêu cầu tỷ lệ BHYT tính ở server từ mã thẻ và client không được gửi tỷ lệ. Lễ tân (hoặc tài khoản lễ tân bị chiếm) có thể đặt 100% cho bệnh nhân không có thẻ để làm giảm số tiền bệnh nhân phải trả (gian lận). Ngoài ra không ghi audit log khi thay đổi tiền.

**Kịch bản khai thác:** Lễ tân gửi POST /invoices/5/coverage với coverage_rate=1.00 cho hóa đơn của bệnh nhân không có thẻ BHYT; patient_amount về 0 mà không có kiểm tra nào đối chiếu với mã thẻ.

**Đề xuất sửa:** Xóa endpoint adjust_coverage cùng form trong detail.html. Nếu cần đổi mức hưởng, để server tính lại từ mã thẻ BHYT của bệnh nhân (hàm tính tỷ lệ trong billing/service.py) rồi gọi service.compute_amounts; không nhận coverage_rate từ client. Nếu bắt buộc có ngoại lệ (chuyển tuyến), cần quy tắc nghiệp vụ mới, giới hạn cho ADMIN và ghi audit log.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** create_app chỉ thêm middleware session, lỗi và metrics; không có middleware nào đặt X-Frame-Options hay CSP frame-ancestors.

**Đề xuất sửa:** Thêm middleware security headers trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY, X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Như F1: không có header chống clickjacking ở bất kỳ middleware nào.

**Đề xuất sửa:** Thêm middleware security headers trong create_app (main.py) với X-Frame-Options: DENY.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware security headers trong create_app (main.py) đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware security headers ở create_app (main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app (main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options, kể cả cho /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app (main.py).

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 39.0 s · 17 lần gọi LLM · 16 lần gọi công cụ · 84997 token vào / 6242 token ra · ≈ $0.1386 · chạm giới hạn: không</sub>
