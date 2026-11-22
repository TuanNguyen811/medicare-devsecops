<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `cb4cc00`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | Cho phép đổi trạng thái hóa đơn PAID → UNPAID (quay ngược luồng) | `app/medicare/billing/service.py:151` | agent | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · Cho phép đổi trạng thái hóa đơn PAID → UNPAID (quay ngược luồng) — `app/medicare/billing/service.py:151`

CWE-841 · OWASP A06 · vi phạm R-17 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** change_status chỉ kiểm tra status nằm trong InvoiceStatus và khác trạng thái hiện tại. Lễ tân có thể POST status=UNPAID lên hóa đơn đã PAID, vi phạm R-17 (không quay ngược). Sau đó có thể thêm dòng dịch vụ vào hóa đơn đã thu tiền, làm thay đổi tổng tiền sau khi thu và dễ gian lận/biển thủ.

**Kịch bản khai thác:** Lễ tân thu tiền hóa đơn, POST /invoices/{id}/status với status=UNPAID, rồi thêm/chỉnh dòng và đánh dấu PAID lại, hoặc để hóa đơn ở trạng thái chưa thu sau khi nhận tiền mặt.

**Đề xuất sửa:** Trong service.change_status chỉ cho phép chuyển UNPAID → PAID (bảng chuyển trạng thái cho phép); từ chối mọi chuyển khác, kể cả PAID → UNPAID, bằng Conflict. Có thể bỏ tham số status tự do ở router và dùng endpoint /pay riêng.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Tìm trong repo không thấy X-Frame-Options hay CSP frame-ancestors, nên ứng dụng không chống clickjacking. Trang hóa đơn có form thu tiền nên có thể bị nhúng iframe. | Thêm middleware trong app factory để mọi response có X-Frame-Options: DENY và CSP frame-ancestors 'none'. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có Content-Security-Policy nào trong repo. | Thêm CSP chặt (default-src 'self', frame-ancestors 'none') trong middleware security headers. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options trên toàn ứng dụng. | Thêm nosniff trong middleware security headers. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Repo không đặt X-Content-Type-Options: nosniff ở đâu. | Thêm X-Content-Type-Options: nosniff vào middleware security headers toàn ứng dụng. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 48.5 s · 25 lần gọi LLM · 14 lần gọi công cụ · 127818 token vào / 7620 token ra · ≈ $0.1932 · chạm giới hạn: không</sub>
