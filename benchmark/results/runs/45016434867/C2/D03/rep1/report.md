<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `743d5ee`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🟢 FP | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/announcement/admin.html:37` | 0.80 |
| 🟢 FP | LOW | semgrep | security.semgrep.medicare.jinja-safe-filter (semgrep) | `app/medicare/templates/home.html:20` | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong mã không thấy middleware nào đặt X-Frame-Options, CSP hay nosniff, nên ứng dụng thiếu header chống clickjacking trên toàn bộ response.

**Đề xuất sửa:** Thêm middleware trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong toàn bộ mã (trang /login cũng không có).

**Đề xuất sửa:** Dùng middleware chung trong create_app (app/medicare/main.py) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Content-Type-Options.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong create_app (app/medicare/main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong mã. CSP cũng là lớp phòng thủ chiều sâu cho nội dung |safe mới của PR.

**Đề xuất sửa:** Thêm header Content-Security-Policy chặt (default-src 'self', không cho inline script) bằng middleware trong create_app (app/medicare/main.py).

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong mã.

**Đề xuất sửa:** Thêm Content-Security-Policy cho mọi response bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong mã.

**Đề xuất sửa:** Thêm Content-Security-Policy cho mọi response bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có CSP nào được đặt trong mã.

**Đề xuất sửa:** Thêm Content-Security-Policy cho mọi response bằng middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong mã.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong app/medicare/main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong mã. /health trả JSON nên rủi ro thấp, nhưng nên xử lý chung.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung trong app/medicare/main.py.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **security.semgrep.medicare.jinja-safe-filter (semgrep)** — `app/medicare/templates/announcement/admin.html:37`: `body_html` không phải dữ liệu thô. Giá trị chỉ được ghi qua `service.create`, hàm này gọi `clean_body` (bleach với allowlist thẻ chặt, thuộc tính chỉ `href`/`title`, giao thức http/https/mailto). Chỉ ADMIN có CSRF mới tạo được. `title` vẫn được escape tự động. Rủi ro còn lại là stored XSS nếu có đường ghi khác bỏ qua `clean_body`, nhưng không thấy đường nào trong PR.
- **security.semgrep.medicare.jinja-safe-filter (semgrep)** — `app/medicare/templates/home.html:20`: Giống F1: `body_html` đã được làm sạch bằng bleach (allowlist) trước khi lưu trong `service.create`, và chỉ ADMIN mới đăng được. Lọc `|safe` áp dụng trên HTML đã làm sạch.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 58.6 s · 27 lần gọi LLM · 17 lần gọi công cụ · 153354 token vào / 8619 token ra · ≈ $0.2274 · chạm giới hạn: không</sub>
