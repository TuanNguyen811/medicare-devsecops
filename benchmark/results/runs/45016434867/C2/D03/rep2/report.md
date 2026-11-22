<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `743d5ee`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🟢 FP | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/announcement/admin.html:37` | 0.85 |
| 🟢 FP | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/home.html:20` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Ứng dụng không đặt header bảo mật nào (tìm X-Frame-Options/CSP/nosniff không có kết quả; chỉ có CatchAllErrors, Session, Metrics middleware).

**Đề xuất sửa:** Thêm middleware toàn cục trong app/medicare/main.py (create_app) đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy chặt cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trên toàn ứng dụng.

**Đề xuất sửa:** Đặt X-Frame-Options/frame-ancestors bằng middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt; CSP còn là lớp phòng thủ chiều sâu cho nội dung |safe mới của PR.

**Đề xuất sửa:** Thêm Content-Security-Policy (default-src 'self', không cho inline script) bằng middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trên toàn ứng dụng.

**Đề xuất sửa:** Đặt CSP bằng middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trên toàn ứng dụng.

**Đề xuất sửa:** Đặt CSP bằng middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trên toàn ứng dụng.

**Đề xuất sửa:** Đặt CSP bằng middleware toàn cục trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware toàn cục ở app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options (cả /health); sửa bằng middleware toàn cục.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware toàn cục ở app/medicare/main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware toàn cục ở app/medicare/main.py.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **security.semgrep.medicare.jinja-safe-filter (semgrep)** — `app/medicare/templates/announcement/admin.html:37`: body_html chỉ được ghi qua service.create, luôn qua bleach.clean với allowlist chặt (không có script/style/on*, giao thức chỉ http/https/mailto). Chỉ ADMIN tạo được. Nên |safe ở đây render HTML đã làm sạch, không phải dữ liệu thô.
- **security.semgrep.medicare.jinja-safe-filter (semgrep)** — `app/medicare/templates/home.html:20`: Như F1: body_html đã được bleach.clean với allowlist chặt trước khi lưu; chỉ ADMIN ghi được. Title vẫn được autoescape.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 68.5 s · 27 lần gọi LLM · 17 lần gọi công cụ · 153357 token vào / 7995 token ra · ≈ $0.1445 · chạm giới hạn: không</sub>
