<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `49fe3a5`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🟢 FP | LOW | semgrep | python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text (semgrep) | `app/medicare/patient/service.py:72` | 0.95 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không tìm thấy chỗ nào trong repo đặt X-Frame-Options hoặc CSP frame-ancestors, nên ZAP báo đúng. Lỗi có sẵn từ trước, không do PR này gây ra.

**Đề xuất sửa:** Thêm middleware dùng chung trong app FastAPI để đặt X-Frame-Options: DENY, hoặc CSP có frame-ancestors 'none', cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo, trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware security headers chung: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo (đã search toàn bộ).

**Đề xuất sửa:** Thêm Content-Security-Policy vào middleware security headers dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo (đã search toàn bộ).

**Đề xuất sửa:** Thêm Content-Security-Policy vào middleware security headers dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo (đã search toàn bộ).

**Đề xuất sửa:** Thêm Content-Security-Policy vào middleware security headers dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo (đã search toàn bộ).

**Đề xuất sửa:** Thêm Content-Security-Policy vào middleware security headers dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo (đã search toàn bộ).

**Đề xuất sửa:** Thêm Content-Security-Policy vào middleware security headers dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options; không có header nào được đặt trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Endpoint /health thiếu X-Content-Type-Options; không có header nào được đặt trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers dùng chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options hay CSP ở bất kỳ đâu. Đây là cấu hình thiếu từ trước, không do PR này gây ra.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware security headers đặt X-Content-Type-Options: nosniff và một CSP phù hợp.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text (semgrep)** — `app/medicare/patient/service.py:72`: Phần được nội suy vào f-string là `column`, lấy từ allowlist `YEAR_FIELDS.get(year_field, YEAR_FIELDS["dob"])`. Giá trị chỉ có thể là `date_of_birth` hoặc `created_at`; input lạ sẽ rơi về mặc định. Giá trị `year` đi qua bind parameter `:year` và đã được ép sang int ở router (4 chữ số ASCII). Người dùng không điều khiển được chuỗi SQL.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 51.0 s · 26 lần gọi LLM · 15 lần gọi công cụ · 94266 token vào / 8036 token ra · ≈ $0.1737 · chạm giới hạn: không</sub>
