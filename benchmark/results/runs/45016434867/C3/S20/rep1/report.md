<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 2 phát hiện mới do Agent tự tìm · commit `e289c57`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | parse_lines không kiểm tra số lượng dương/giới hạn: số âm hoặc 0 làm giảm tổng tiền | `app/medicare/billing/service.py:115` | 0.90 |
| 🔴 TP | HIGH | agent | change_status cho phép đảo ngược PAID → UNPAID, vi phạm luồng hóa đơn | `app/medicare/billing/service.py:148` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.50 |

### Chi tiết

#### 🔴 TP · HIGH · parse_lines không kiểm tra số lượng dương/giới hạn: số âm hoặc 0 làm giảm tổng tiền — `app/medicare/billing/service.py:115`

CWE-20 · OWASP A06 · vi phạm R-17 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** Số lượng chỉ được ép int(quantity), không kiểm tra > 0 hay giới hạn trên. Ràng buộc min=1/max=99 chỉ ở HTML phía client. Gửi quantity=-5 tạo dòng có amount âm, giảm total_amount và patient_amount (thậm chí âm); R-17 yêu cầu số nguyên dương. Số quá lớn có thể vượt Numeric(12,0) gây lỗi 500.

**Kịch bản khai thác:** Lễ tân gửi POST /invoices/{id}/lines với service_code=GIUONG-NOI, quantity=-4 để trừ 1.000.000 VND khỏi hóa đơn, hoặc thêm dòng âm sau dòng dương để giảm số tiền bệnh nhân phải trả.

**Đề xuất sửa:** Trong service.parse_lines, sau khi int(quantity), từ chối nếu quantity < 1 hoặc > 99 (hằng số MAX_QUANTITY) bằng BillingError. Thêm CheckConstraint quantity > 0 cho InvoiceLine trong models.py và migration 0004. Thêm test cho số âm, 0 và số rất lớn.

#### 🔴 TP · HIGH · change_status cho phép đảo ngược PAID → UNPAID, vi phạm luồng hóa đơn — `app/medicare/billing/service.py:148`

CWE-840 · OWASP A06 · vi phạm R-17 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** change_status chỉ kiểm tra status là thành viên của InvoiceStatus và khác trạng thái hiện tại, nên POST status=UNPAID lên hóa đơn đã PAID được chấp nhận. R-17 yêu cầu chỉ UNPAID → PAID và không quay ngược. Hậu quả: lễ tân có thể mở lại hóa đơn đã thu, thêm/sửa dòng dịch vụ rồi thu lại, che giấu việc gian lận tiền; không có audit.

**Kịch bản khai thác:** Lễ tân thu tiền (PAID), sau đó gửi POST /invoices/{id}/status với status=UNPAID, thêm dịch vụ qua /lines, hoặc thu lại và biển thủ khoản chênh lệch.

**Đề xuất sửa:** Trong service.change_status, dùng bảng chuyển trạng thái cho phép chỉ {UNPAID: PAID}; mọi chuyển khác (đặc biệt PAID → UNPAID) phải raise Conflict. Nên bỏ tham số status từ client và dùng endpoint chỉ làm UNPAID → PAID như mark_paid cũ. Thêm test cho việc đảo ngược trạng thái.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP báo thiếu header chống clickjacking (X-Frame-Options / CSP frame-ancestors) trên GET /. Trong code được cung cấp không có middleware nào đặt header bảo mật nên không có bằng chứng để bác bỏ.

**Đề xuất sửa:** Thêm middleware toàn cục trong app factory (app/medicare) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking; đây là trang nhập mật khẩu nên dễ bị framing. Cùng nguyên nhân gốc với F1.

**Đề xuất sửa:** Dùng chung middleware security headers toàn cục với X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên GET /. Không có cấu hình header trong code được cung cấp.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Endpoint /health thiếu X-Content-Type-Options. Tác động rất thấp vì nội dung đơn giản, nhưng cùng nguyên nhân gốc thiếu middleware header.

**Đề xuất sửa:** Thêm header nosniff trong middleware toàn cục để bao gồm cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff trên /login; không có cấu hình header trong code được cung cấp.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Phản hồi POST /appointments không có CSP. Thường là redirect 303 nên tác động thấp, nhưng gốc rễ là thiếu CSP toàn cục cho ứng dụng Jinja2.

**Đề xuất sửa:** Đặt Content-Security-Policy mặc định (default-src 'self'; frame-ancestors 'none') trong middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /appointments/{id}/cancel; cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Đặt CSP trong middleware toàn cục; không cần sửa từng route.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /appointments/{id}/confirm; cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Đặt CSP trong middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients; cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Đặt CSP trong middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients/{id}/edit; cùng nguyên nhân gốc với F6.

**Đề xuất sửa:** Đặt CSP trong middleware toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 52.5 s · 3 lần gọi LLM · 13 lần gọi công cụ · 76156 token vào / 8996 token ra · ≈ $0.2560 · chạm giới hạn: không</sub>
