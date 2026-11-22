<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🟡 2 cần người xem

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `a9d4eb0`

### 🟡 Cần người xem

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🟡 NEEDS_REVIEW | LOW | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/announcement/admin.html:37` | semgrep | 0.85 |
| 🟡 NEEDS_REVIEW | LOW | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/home.html:20` | semgrep | 0.85 |

### Chi tiết

#### 🟡 NEEDS_REVIEW · LOW · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/announcement/admin.html:37`

CWE-79 · độ tin cậy 0.85 · nguồn: semgrep

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] body_html chỉ được ghi qua service.create, luôn qua clean_body (bleach allowlist chặt: không script/on*/style, giao thức chỉ http/https/mailto, strip comment). |safe chỉ áp dụng lên HTML đã làm sạch; chỉ ADMIN có thể ghi. Không có đường ghi nào khác vào body_html.

#### 🟡 NEEDS_REVIEW · LOW · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/home.html:20`

CWE-79 · độ tin cậy 0.85 · nguồn: semgrep

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] Như F1: home.html chỉ render body_html đã qua bleach.clean với allowlist chặt khi lưu; chỉ ADMIN tạo thông báo.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Không có middleware nào đặt X-Frame-Options hay CSP frame-ancestors (search_code không thấy). Ứng dụng có form thay đổi dữ liệu nên có nguy cơ clickjacking. | Thêm middleware security headers trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có Content-Security-Policy ở đâu; CSP là lớp phòng thủ chiều sâu, nhất là khi có render HTML \|safe. | Thêm header Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware chung ở create_app. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options trên GET /. | Thêm header nosniff qua middleware chung trong app/medicare/main.py. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Thiếu X-Content-Type-Options: nosniff; không có code đặt header này. | Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 59.5 s · 27 lần gọi LLM · 16 lần gọi công cụ · 137903 token vào / 9989 token ra · ≈ $0.1704 · chạm giới hạn: không</sub>
