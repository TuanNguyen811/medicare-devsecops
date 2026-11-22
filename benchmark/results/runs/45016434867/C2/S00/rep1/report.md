<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `4705039`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.75 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** create_app chỉ thêm CatchAllErrors, Session và Metrics middleware. Không có middleware nào đặt X-Frame-Options hay CSP frame-ancestors, nên các trang có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Trong app/medicare/main.py (create_app), thêm một middleware đặt header bảo mật cho mọi response: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking vì app không đặt header bảo mật nào. Đây là trang đăng nhập nên rủi ro cao hơn.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong create_app (main.py) để đặt X-Frame-Options: DENY.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** App không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware header bảo mật ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** App không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** App không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật ở create_app (main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** App không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật ở create_app (main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật ở create_app (main.py).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff, kể cả cho /health. Rủi ro thấp vì /health trả JSON.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật ở create_app (main.py).

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 31.2 s · 14 lần gọi LLM · 13 lần gọi công cụ · 61265 token vào / 4832 token ra · ≈ $0.0987 · chạm giới hạn: không</sub>
