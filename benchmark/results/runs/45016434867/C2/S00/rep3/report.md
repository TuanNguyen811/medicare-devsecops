<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `4705039`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Ứng dụng không đặt header X-Frame-Options hay CSP frame-ancestors; create_app chỉ thêm middleware lỗi, session và metrics. Trang có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Thêm một middleware security headers trong create_app (app/medicare/main.py) để đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Trang /login cũng thiếu header chống clickjacking, vì không có middleware nào đặt X-Frame-Options hay frame-ancestors. Trang đăng nhập đặc biệt dễ bị UI redress.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (app/medicare/main.py), đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong bất kỳ response nào, gồm POST /appointments, làm mất lớp giảm thiểu XSS.

**Đề xuất sửa:** Thêm header Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') qua middleware security headers trong create_app (app/medicare/main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP trên mọi response, gồm POST /appointments/{appointment_id}/confirm.

**Đề xuất sửa:** Thêm CSP toàn cục bằng middleware security headers trong create_app (app/medicare/main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP trên mọi response, gồm POST /patients.

**Đề xuất sửa:** Thêm CSP toàn cục bằng middleware security headers trong create_app (app/medicare/main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP trên mọi response, gồm POST /patients/{patient_id}/edit.

**Đề xuất sửa:** Thêm CSP toàn cục bằng middleware security headers trong create_app (app/medicare/main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /; không có middleware nào đặt header này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware security headers trong create_app (app/medicare/main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân là không có middleware đặt header bảo mật.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers ở create_app (app/medicare/main.py), áp dụng cho cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có code nào đặt X-Content-Type-Options: nosniff, nên trình duyệt có thể đoán MIME type.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers ở create_app (app/medicare/main.py), thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 31.8 s · 14 lần gọi LLM · 13 lần gọi công cụ · 46039 token vào / 4870 token ra · ≈ $0.0724 · chạm giới hạn: không</sub>
