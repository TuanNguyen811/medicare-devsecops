<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 2 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `1e62304`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/insurance-check:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🟢 FP | LOW | bandit | B404 (bandit) | `app/medicare/patient/insurance_check.py:10` | 0.90 |
| 🟢 FP | LOW | bandit | B603 (bandit) | `app/medicare/patient/insurance_check.py:57` | 0.85 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options hay frame-ancestors ở đâu, nên ứng dụng thiếu header chống clickjacking (trang có form thao tác dữ liệu y tế).

**Đề xuất sửa:** Thêm middleware security headers trong app factory để mọi response có X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login dễ bị framing.

**Đề xuất sửa:** Dùng chung middleware security headers: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff cho mọi response trong middleware security headers.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware security headers.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/insurance-check:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo, kể cả route mới insurance-check.

**Đề xuất sửa:** Thêm Content-Security-Policy qua middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options cả với /health; sửa chung bằng middleware.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff qua middleware chung.

<details><summary>🟢 Báo nhầm (FP): 2</summary>

- **B404 (bandit)** — `app/medicare/patient/insurance_check.py:10`: B404 chỉ là cảnh báo khi import subprocess; cách dùng an toàn (argv list, không shell, đường dẫn từ cấu hình).
- **B603 (bandit)** — `app/medicare/patient/insurance_check.py:57`: subprocess.run nhận list argv, không shell=True. Mã thẻ được kiểm bằng is_valid_insurance_number (regex ASCII), họ tên chuẩn hóa và giới hạn độ dài, mỗi giá trị đi dạng --name=value nên không bị hiểu là option. Executable lấy từ Settings (env), không từ người dùng.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 34.9 s · 18 lần gọi LLM · 17 lần gọi công cụ · 91184 token vào / 4972 token ra · ≈ $0.0856 · chạm giới hạn: không</sub>
