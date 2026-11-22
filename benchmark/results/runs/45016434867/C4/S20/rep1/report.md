<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `e289c57`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | change_status cho phép đảo hóa đơn PAID về UNPAID rồi sửa dòng dịch vụ/tổng tiền | `app/medicare/billing/service.py:144` | 0.80 |
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

#### 🔴 TP · HIGH · change_status cho phép đảo hóa đơn PAID về UNPAID rồi sửa dòng dịch vụ/tổng tiền — `app/medicare/billing/service.py:144`

CWE-840 · OWASP A06 · độ tin cậy 0.80 · nguồn: agent

**Phân tích:** Endpoint cũ /pay chỉ cho UNPAID->PAID một chiều (mark_paid ném Conflict nếu đã trả). change_status mới chấp nhận bất kỳ trạng thái hợp lệ nào khác trạng thái hiện tại, kể cả PAID->UNPAID. Lễ tân có thể hoàn tác hóa đơn đã thu tiền, thêm dòng dịch vụ (add_lines chỉ chặn khi status != UNPAID) làm đổi total_amount, rồi thu lại — thao tác gian lận/biển thủ tiền thu, vô hiệu bất biến của hóa đơn đã thanh toán. Không có audit log.

**Kịch bản khai thác:** Lễ tân POST /invoices/{id}/status với status=UNPAID trên hóa đơn đã PAID, sau đó POST /lines để đổi tổng tiền, rồi POST status=PAID lại; số tiền đã thu không còn khớp.

**Đề xuất sửa:** Trong service.change_status chỉ cho phép chuyển UNPAID -> PAID (như mark_paid cũ), từ chối mọi chuyển ngược với Conflict; nếu cần hoàn tiền thì làm quy trình riêng cho ADMIN có ghi audit log. Tách endpoint thu tiền khỏi tham số status tuỳ ý từ client.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors (search_code không thấy). create_app chỉ có Catch-all, Session, Metrics. Trang có form thu tiền nên có nguy cơ clickjacking.

**Đề xuất sửa:** Thêm một middleware trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống framing cho /login; trang đăng nhập có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware security headers chung trong create_app: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP trong ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app.

**Đề xuất sửa:** Thêm header nosniff qua middleware chung trong create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health do không có middleware header chung.

**Đề xuất sửa:** Thêm header nosniff qua middleware chung trong create_app.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware đặt X-Content-Type-Options: nosniff trong toàn ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers chung trong create_app đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 38.2 s · 17 lần gọi LLM · 16 lần gọi công cụ · 112449 token vào / 5947 token ra · ≈ $0.1468 · chạm giới hạn: không</sub>
