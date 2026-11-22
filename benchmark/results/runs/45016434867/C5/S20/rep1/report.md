<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `e289c57`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | change_status cho phép chuyển hóa đơn PAID → UNPAID (vi phạm luồng R-17) | `app/medicare/billing/service.py:151` | 0.90 |
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

#### 🔴 TP · HIGH · change_status cho phép chuyển hóa đơn PAID → UNPAID (vi phạm luồng R-17) — `app/medicare/billing/service.py:151`

CWE-840 · OWASP A06 · vi phạm R-17 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** service.change_status chỉ kiểm tra status hợp lệ và khác trạng thái hiện tại, nên POST status=UNPAID trên hóa đơn đã PAID sẽ đưa hóa đơn quay ngược lại. R-17 chỉ cho phép UNPAID → PAID, không quay ngược. Sau khi hoàn tác, add_lines lại cho thêm dòng và đổi tổng tiền của hóa đơn đã thu.

**Kịch bản khai thác:** Lễ tân thu tiền (PAID), rồi POST /invoices/{id}/status với status=UNPAID, thêm hoặc sửa dòng dịch vụ, rồi đặt lại PAID. Tổng tiền thay đổi sau khi đã thu, có thể dùng để biển thủ hoặc gian lận.

**Đề xuất sửa:** Trong service.change_status, dùng bảng chuyển trạng thái cho phép chỉ có UNPAID → PAID. Mọi chuyển khác, gồm PAID → UNPAID, phải bị từ chối bằng Conflict. Thêm test cho việc từ chối quay ngược.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay CSP frame-ancestors ở bất kỳ đâu trong repo, nên ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware đặt header bảo mật cho mọi response: X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Frame-Options hay frame-ancestors trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Thêm middleware đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở bất kỳ đâu, nên không có lớp giảm thiểu XSS.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware header bảo mật dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng, gồm cả /health.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware header bảo mật dùng chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở bất kỳ đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware header bảo mật dùng chung, đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 39.2 s · 17 lần gọi LLM · 15 lần gọi công cụ · 140107 token vào / 5688 token ra · ≈ $0.1654 · chạm giới hạn: không</sub>
