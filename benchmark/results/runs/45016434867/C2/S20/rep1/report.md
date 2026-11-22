<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `e289c57`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Số lượng dòng hóa đơn không kiểm tra là số nguyên dương | `app/medicare/billing/service.py:116` | 0.90 |
| 🔴 TP | HIGH | agent | change_status cho phép hóa đơn quay ngược PAID → UNPAID | `app/medicare/billing/service.py:144` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · Số lượng dòng hóa đơn không kiểm tra là số nguyên dương — `app/medicare/billing/service.py:116`

CWE-20 · OWASP A06 · vi phạm R-17 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** parse_lines chỉ gọi int(quantity), không kiểm tra > 0 và không có giới hạn trên (min/max chỉ ở HTML, client có thể bỏ qua). Số lượng 0 hoặc âm tạo amount âm, làm giảm tổng tiền hóa đơn (kể cả xuống âm). Số quá lớn có thể làm tràn Numeric(12,0) và gây lỗi 500. R-17 yêu cầu số lượng là số nguyên dương.

**Kịch bản khai thác:** Gửi POST /invoices/5/lines với service_code=XN-CTM, quantity=-100 để làm giảm tổng hóa đơn, hoặc quantity=10**15 để gây lỗi DB.

**Đề xuất sửa:** Trong service.parse_lines, sau khi int(quantity), từ chối giá trị < 1 và đặt giới hạn trên (ví dụ 99, khớp với form) bằng BillingError. Có thể thêm CheckConstraint quantity > 0 cho InvoiceLine và migration 0004.

#### 🔴 TP · HIGH · change_status cho phép hóa đơn quay ngược PAID → UNPAID — `app/medicare/billing/service.py:144`

CWE-840 · OWASP A06 · vi phạm R-17 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** service.change_status chỉ kiểm tra status nằm trong InvoiceStatus và khác trạng thái hiện tại. Do đó POST /invoices/{id}/status với status=UNPAID trên hóa đơn đã PAID vẫn được chấp nhận. Việc này vi phạm R-17 (chỉ UNPAID→PAID, không quay ngược). Sau khi hoàn tác, lễ tân có thể thêm dòng dịch vụ vào hóa đơn đã thu tiền, rồi thu lại tiền (khả năng biển thủ).

**Kịch bản khai thác:** Lễ tân gửi POST /invoices/5/status với status=UNPAID cho hóa đơn đã PAID, thêm dòng dịch vụ hoặc chuyển lại để chỉnh sổ sách tiền thu.

**Đề xuất sửa:** Trong service.change_status, định nghĩa bảng chuyển trạng thái cho phép chỉ {UNPAID: {PAID}} và từ chối (Conflict/BillingError) mọi chuyển đổi khác, đặc biệt PAID→UNPAID. Giữ route chỉ dành cho receptionist_user.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay frame-ancestors ở bất kỳ đâu trong repo, nên ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers dùng chung (app factory) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Frame-Options/frame-ancestors trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware security headers chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt chẽ (default-src 'self', frame-ancestors 'none') qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health do không có header chung nào được đặt.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options: nosniff ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 38.7 s · 16 lần gọi LLM · 15 lần gọi công cụ · 91858 token vào / 5924 token ra · ≈ $0.1550 · chạm giới hạn: không</sub>
