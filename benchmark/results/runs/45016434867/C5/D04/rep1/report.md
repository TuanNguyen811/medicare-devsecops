<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `ef2829f`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trong app/medicare/main.py chỉ có SessionMiddleware, CatchAllErrorsMiddleware và MetricsMiddleware. Không có chỗ nào đặt X-Frame-Options hay frame-ancestors, nên trang có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Thêm một middleware security headers trong app/medicare/main.py. Middleware này đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware nào đặt header chống clickjacking, nên trang /login cũng bị ảnh hưởng.

**Đề xuất sửa:** Dùng chung middleware security headers trong app/medicare/main.py, đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ chỗ nào.

**Đề xuất sửa:** Thêm CSP chặt trong middleware security headers ở app/medicare/main.py, ví dụ default-src 'self'; frame-ancestors 'none'. Điều chỉnh theo các tài nguyên CDN mà template đang dùng.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ chỗ nào.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ chỗ nào.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ chỗ nào.

**Đề xuất sửa:** Thêm CSP trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options trong toàn bộ ứng dụng.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Endpoint /health cũng thiếu X-Content-Type-Options vì ứng dụng không có middleware nào đặt header này.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware security headers ở app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Toàn bộ mã nguồn không có chỗ nào đặt X-Content-Type-Options.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers ở app/medicare/main.py, đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 45.3 s · 23 lần gọi LLM · 13 lần gọi công cụ · 115884 token vào / 7250 token ra · ≈ $0.1670 · chạm giới hạn: không</sub>
