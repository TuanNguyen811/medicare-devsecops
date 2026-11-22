<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `ef2829f`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.50 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP đo được phản hồi GET / thiếu X-Frame-Options / CSP frame-ancestors. Đây là kết quả thực nghiệm trên phản hồi HTTP. Trong phiên này tôi không có công cụ để đọc middleware nên không thể bác bỏ. Lỗi là cấu hình toàn ứng dụng, không nằm trong code của PR. Ứng dụng có form thay đổi dữ liệu y tế nên clickjacking là rủi ro thật.

**Đề xuất sửa:** Thêm một middleware chung (trong app factory của FastAPI) gắn header X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking, cùng nguyên nhân gốc với F1 (không có middleware header bảo mật toàn cục).

**Đề xuất sửa:** Dùng chung middleware security headers: X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi route, gồm /login.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** GET / thiếu X-Content-Type-Options: nosniff; cùng nguyên nhân gốc với F5.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** GET /health thiếu X-Content-Type-Options. Rủi ro rất thấp vì endpoint trả dữ liệu tĩnh, nhưng cùng nguyên nhân gốc, sửa bằng middleware chung.

**Đề xuất sửa:** Middleware security headers toàn cục thêm X-Content-Type-Options: nosniff, áp dụng cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** ZAP ghi nhận /login thiếu X-Content-Type-Options: nosniff. Đây là lỗi cấu hình toàn cục, mức ảnh hưởng thấp.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers chung, thêm X-Content-Type-Options: nosniff cho mọi phản hồi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Phản hồi của POST /appointments thiếu Content-Security-Policy. Phản hồi chủ yếu là redirect hoặc trang lỗi nên ảnh hưởng thấp, nhưng nguyên nhân là không có CSP toàn cục.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware chung cho mọi phản hồi, kể cả lỗi 4xx và redirect.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Cùng nguyên nhân gốc với F6: thiếu CSP toàn cục trên POST /appointments/{appointment_id}/confirm.

**Đề xuất sửa:** Cấu hình CSP trong middleware chung, không cấu hình riêng từng route.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Cùng nguyên nhân gốc với F6: thiếu CSP toàn cục trên POST /patients.

**Đề xuất sửa:** Thêm CSP qua middleware security headers chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Cùng nguyên nhân gốc với F6: thiếu CSP toàn cục trên POST /patients/{patient_id}/edit.

**Đề xuất sửa:** Thêm CSP qua middleware security headers chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 44.1 s · 3 lần gọi LLM · 10 lần gọi công cụ · 93032 token vào / 7118 token ra · ≈ $0.2680 · chạm giới hạn: không</sub>
