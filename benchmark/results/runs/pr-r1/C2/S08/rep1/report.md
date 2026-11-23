<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 1 lỗi cần sửa · 🟡 1 cần người xem

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `ca0e00e`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | generic-api-key (gitleaks) | `app/medicare/appointment/sms.py:13` | gitleaks | 0.90 |
| 🟡 NEEDS_REVIEW | LOW | B310 (bandit) | `app/medicare/appointment/sms.py:50` | bandit | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/appointment/sms.py:13`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** sms.py dòng 13-14 gán ESMS_API_KEY và ESMS_SECRET_KEY là hằng số trong mã nguồn (Gitleaks và Bandit cùng báo). Vi phạm R-09: secret chỉ được đọc từ biến môi trường. Khoá đã nằm trong lịch sử git nên có thể bị lạm dụng.

**Kịch bản khai thác:** Ai đọc được repo sẽ lấy ApiKey/SecretKey eSMS và gửi SMS mạo danh brandname MEDICARE, gây tốn tiền và lừa đảo bệnh nhân.

Gộp các phát hiện: `bandit:B105:app/medicare/appointment/sms.py:14`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:13`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:14`

**Đề xuất sửa:** Thu hồi và xoay (rotate) khoá eSMS hiện tại. Trong sms.py, đọc ESMS_API_KEY và ESMS_SECRET_KEY từ biến môi trường qua cơ chế cấu hình của app (như SECRET_KEY, R-09), và từ chối gửi khi thiếu. Xoá khoá khỏi lịch sử git.

#### 🟡 NEEDS_REVIEW · LOW · B310 (bandit) — `app/medicare/appointment/sms.py:50`

CWE-22 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] URL truyền vào urlopen là hằng số https cố định ESMS_URL, không có dữ liệu người dùng nên không thể dùng scheme file:/ hay URL tuỳ ý (R-14 được giữ).

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | search_code không thấy nơi nào đặt X-Frame-Options hay frame-ancestors, nên ứng dụng không chống clickjacking. | Thêm một middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/confirm`, `POST /appointments/{appointment_id}/remind`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có Content-Security-Policy nào được đặt trong mã. | Middleware toàn cục đặt CSP chặt (default-src 'self', frame-ancestors 'none'). |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options trên mọi phản hồi. | Middleware toàn cục thêm X-Content-Type-Options: nosniff. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Không có mã nào đặt X-Content-Type-Options. | Middleware toàn cục thêm X-Content-Type-Options: nosniff. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 50.6 s · 29 lần gọi LLM · 17 lần gọi công cụ · 78046 token vào / 8765 token ra · ≈ $0.1850 · chạm giới hạn: không</sub>
