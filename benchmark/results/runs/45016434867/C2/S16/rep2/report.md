<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `5aac359`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/reschedule:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** create_app trong app/medicare/main.py chỉ thêm CatchAllErrorsMiddleware, SessionMiddleware và MetricsMiddleware. Không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors, nên trang có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Thêm một middleware security headers vào create_app trong main.py. Middleware này đặt X-Frame-Options: DENY, hoặc CSP có frame-ancestors 'none', trên mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking. Nguyên nhân là không có middleware nào trong main.py đặt X-Frame-Options hoặc frame-ancestors.

**Đề xuất sửa:** Dùng middleware security headers chung trong main.py, đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu (đã search toàn repo). Không có lớp phòng thủ chiều sâu chống XSS.

**Đề xuất sửa:** Thêm CSP chặt vào middleware security headers chung trong main.py, ví dụ default-src 'self'; frame-ancestors 'none'. Kiểm tra lại các template dùng inline script hoặc style.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/reschedule:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Các response của route reschedule, bao gồm reschedule.html, không có CSP vì ứng dụng không có middleware đặt header này.

**Đề xuất sửa:** Thêm CSP vào middleware security headers chung để áp dụng cho mọi route.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** POST /patients không trả CSP, cùng nguyên nhân với F6: ứng dụng không đặt header này ở đâu.

**Đề xuất sửa:** Thêm CSP vào middleware security headers chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** POST /patients/{patient_id}/edit không trả CSP, cùng nguyên nhân với F6.

**Đề xuất sửa:** Thêm CSP vào middleware security headers chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Thiếu header nosniff, cùng nguyên nhân với F5: repo không có code nào đặt header này.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Endpoint /health cũng thiếu nosniff vì repo không có middleware đặt header này. Rủi ro thấp.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có code nào trong repo đặt X-Content-Type-Options: nosniff. Trình duyệt có thể đoán MIME type của response.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware security headers chung trong main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 46.4 s · 24 lần gọi LLM · 14 lần gọi công cụ · 135858 token vào / 7292 token ra · ≈ $0.1310 · chạm giới hạn: không</sub>
