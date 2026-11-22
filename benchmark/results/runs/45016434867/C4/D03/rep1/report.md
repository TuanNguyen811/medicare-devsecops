<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `743d5ee`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🟢 FP | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/announcement/admin.html:37` | 0.80 |
| 🟢 FP | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/home.html:20` | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không có middleware nào đặt header bảo mật (X-Frame-Options/frame-ancestors, X-Content-Type-Options, CSP); tìm kiếm trong code không có kết quả. create_app chỉ thêm Session/Metrics/CatchAll middleware.

**Đề xuất sửa:** Thêm một middleware trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY, X-Content-Type-Options: nosniff và Content-Security-Policy (default-src 'self'; frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu header chống clickjacking trên toàn ứng dụng, không có middleware đặt header.

**Đề xuất sửa:** Thêm middleware header bảo mật toàn cục trong create_app (X-Frame-Options: DENY / CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu; đáng kể vì trang hiển thị HTML qua |safe (lớp phòng thủ chiều sâu).

**Đề xuất sửa:** Thêm CSP (default-src 'self'; frame-ancestors 'none') qua middleware toàn cục trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Thêm CSP qua middleware toàn cục trong create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options.

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options, kể cả với /health.

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục đặt X-Content-Type-Options: nosniff trong create_app.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **security.semgrep.medicare.jinja-safe-filter (semgrep)** — `app/medicare/templates/announcement/admin.html:37`: body_html chỉ do admin nhập và luôn được làm sạch bằng bleach.clean với allowlist chặt (không có script/style/on*, protocol chỉ http/https/mailto) trước khi lưu; đường ghi duy nhất là service.create. |safe chỉ áp dụng lên HTML đã được sanitize.
- **security.semgrep.medicare.jinja-safe-filter (semgrep)** — `app/medicare/templates/home.html:20`: Cùng nguồn dữ liệu body_html đã qua bleach.clean với allowlist chặt trước khi lưu; chỉ admin tạo được. Không có đường nào ghi body_html chưa sanitize.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 57.9 s · 28 lần gọi LLM · 18 lần gọi công cụ · 152511 token vào / 9245 token ra · ≈ $0.2087 · chạm giới hạn: không</sub>
