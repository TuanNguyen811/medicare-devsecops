<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `749e458`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | Client gửi tỷ lệ BHYT lên, vi phạm R-04/R-17 (tính ở server) | `app/medicare/billing/router.py:109` | agent | 0.85 |

### Chi tiết

#### 🔴 TP · HIGH · Client gửi tỷ lệ BHYT lên, vi phạm R-04/R-17 (tính ở server) — `app/medicare/billing/router.py:109`

CWE-639 · OWASP A06 · vi phạm R-04 · độ tin cậy 0.85 · nguồn: agent

**Phân tích:** Route POST /invoices/{invoice_id}/coverage nhận coverage_rate từ form do client gửi và ghi trực tiếp vào invoice.coverage_rate cùng số tiền BHYT/bệnh nhân. Chỉ kiểm tra khoảng 0..1, không đối chiếu mã thẻ BHYT. Lễ tân (hoặc phiên bị chiếm/CSRF-bypass) có thể đặt 100% cho bệnh nhân không có thẻ, gây gian lận/thất thoát viện phí. Không có audit log cho thay đổi này.

**Kịch bản khai thác:** Lễ tân gửi POST /invoices/123/coverage với coverage_rate=1.00 cho bệnh nhân không có thẻ BHYT; patient_amount về 0 và hóa đơn được thu với số tiền sai.

**Đề xuất sửa:** Bỏ tham số coverage_rate do client gửi trong adjust_coverage (app/medicare/billing/router.py). Tính lại tỷ lệ ở server từ mã thẻ BHYT hiện tại của bệnh nhân bằng hàm tính tỷ lệ trong billing/service.py rồi gọi service.compute_amounts. Nếu cần ngoại lệ (chuyển tuyến), chỉ cho chọn từ allowlist có kiểm tra phía server, yêu cầu quyền bổ sung và ghi audit log; bỏ form chọn mức trong detail.html.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | create_app chỉ thêm CatchAllErrorsMiddleware, SessionMiddleware, MetricsMiddleware; không có middleware nào đặt X-Frame-Options hoặc frame-ancestors. | Thêm middleware security headers trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có Content-Security-Policy nào được đặt trong ứng dụng. | Thêm Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware security headers ở create_app. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options, cùng nguyên nhân F5. | Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Không có middleware đặt X-Content-Type-Options: nosniff. | Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 58.4 s · 26 lần gọi LLM · 15 lần gọi công cụ · 116870 token vào / 10045 token ra · ≈ $0.2015 · chạm giới hạn: không</sub>
