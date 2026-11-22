<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 1 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `743d5ee`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🟡 NEEDS_REVIEW | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/announcement/admin.html:37` | 0.85 |
| 🟢 FP | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/home.html:20` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Frame-Options hoặc CSP frame-ancestors (search_code không thấy). create_app chỉ có CatchAll/Session/Metrics middleware.

**Đề xuất sửa:** Thêm middleware security headers trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F3: không có header chống clickjacking toàn ứng dụng.

**Đề xuất sửa:** Dùng chung middleware security headers trong create_app (main.py): X-Frame-Options DENY / frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong mã.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers trong create_app đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP; đáng kể vì PR render HTML do admin nhập (|safe), CSP là lớp phòng thủ chiều sâu.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') qua middleware trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F8: thiếu CSP toàn ứng dụng.

**Đề xuất sửa:** Middleware CSP toàn cục trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F8: thiếu CSP.

**Đề xuất sửa:** Middleware CSP toàn cục trong create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Cùng nguyên nhân F8: thiếu CSP.

**Đề xuất sửa:** Middleware CSP toàn cục trong create_app.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu nosniff trên toàn ứng dụng.

**Đề xuất sửa:** Middleware security headers trong create_app đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health không có nosniff; rủi ro thấp, cùng nguyên nhân thiếu middleware headers.

**Đề xuất sửa:** Middleware security headers toàn cục trong create_app đặt nosniff.

#### 🟡 NEEDS_REVIEW · LOW · security.semgrep.medicare.jinja-safe-filter (semgrep) — `app/medicare/templates/announcement/admin.html:37`

CWE-79 · độ tin cậy 0.85 · nguồn: semgrep

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] body_html chỉ được ghi qua service.create, luôn qua bleach.clean với allowlist chặt (không script/style/on*, giao thức chỉ http/https/mailto). Chỉ ADMIN đăng. |safe trên dữ liệu đã làm sạch là chấp nhận được. Lưu ý: phụ thuộc vào việc không có đường ghi nào khác vào body_html.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **security.semgrep.medicare.jinja-safe-filter (semgrep)** — `app/medicare/templates/home.html:20`: Như F1: body_html đã được bleach.clean bằng allowlist chặt trước khi lưu; title vẫn được auto-escape.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 57.0 s · 29 lần gọi LLM · 19 lần gọi công cụ · 160393 token vào / 9601 token ra · ≈ $0.1701 · chạm giới hạn: không</sub>
