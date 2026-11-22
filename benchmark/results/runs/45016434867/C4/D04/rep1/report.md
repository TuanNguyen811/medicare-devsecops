<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `ef2829f`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |

### Chi tiết

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header X-Frame-Options hay CSP frame-ancestors ở bất kỳ đâu trong app; app/medicare/main.py chỉ có Session, CatchAllErrors và Metrics middleware. Thiếu cấu hình header bảo mật (không do PR này gây ra).

**Đề xuất sửa:** Thêm một middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và Content-Security-Policy có frame-ancestors 'none' cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware header bảo mật chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware header bảo mật chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login không có X-Frame-Options hay frame-ancestors; không có middleware nào đặt header này.

**Đề xuất sửa:** Dùng middleware header bảo mật chung trong app/medicare/main.py (X-Frame-Options: DENY, CSP frame-ancestors 'none').

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options: nosniff.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware header bảo mật chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có header Content-Security-Policy nào được đặt trong app.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt chẽ qua middleware header bảo mật chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có header Content-Security-Policy nào được đặt trong app.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt chẽ qua middleware header bảo mật chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có header Content-Security-Policy nào được đặt trong app.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt chẽ qua middleware header bảo mật chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có header Content-Security-Policy nào được đặt trong app.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt chẽ qua middleware header bảo mật chung trong app/medicare/main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 47.0 s · 24 lần gọi LLM · 14 lần gọi công cụ · 94000 token vào / 7138 token ra · ≈ $0.1644 · chạm giới hạn: không</sub>
