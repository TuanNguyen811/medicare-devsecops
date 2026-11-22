<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `5aac359`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/reschedule:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong toàn repo không thấy nơi nào đặt X-Frame-Options, Content-Security-Policy hay frame-ancestors, nên ứng dụng không chống clickjacking.

**Đề xuất sửa:** Thêm một middleware dùng chung trong app factory của FastAPI để đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Trang /login thiếu header chống clickjacking. Repo không có cấu hình header bảo mật nào.

**Đề xuất sửa:** Dùng chung middleware security headers: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm header Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/reschedule:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Route reschedule mới trả HTML mà không có CSP. Repo không có cấu hình CSP nào.

**Đề xuất sửa:** Đặt CSP trong middleware dùng chung để áp dụng cho cả route reschedule.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt CSP ở bất kỳ đâu.

**Đề xuất sửa:** Đặt CSP trong middleware dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt CSP ở bất kỳ đâu.

**Đề xuất sửa:** Đặt CSP trong middleware dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có nơi nào đặt X-Content-Type-Options trong repo.

**Đề xuất sửa:** Trong middleware security headers, đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Endpoint /health thiếu X-Content-Type-Options. Mức ảnh hưởng thấp vì đây là endpoint JSON. Cách sửa vẫn là dùng chung middleware.

**Đề xuất sửa:** Middleware security headers dùng chung cần đặt nosniff cho cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có nơi nào đặt X-Content-Type-Options trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers, đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 43.5 s · 23 lần gọi LLM · 13 lần gọi công cụ · 112819 token vào / 7003 token ra · ≈ $0.1203 · chạm giới hạn: không</sub>
