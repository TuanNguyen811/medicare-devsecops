<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `bfd2192`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | trivy | CVE-2020-14343 (trivy) | `app/uv.lock:1` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |
| 🔴 TP | LOW | semgrep | package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) | `app/pyproject.toml:43` | 0.50 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · CVE-2020-14343 (trivy) — `app/uv.lock:1`

CWE-502 · OWASP A03 · độ tin cậy 0.95 · nguồn: trivy

**Phân tích:** PyYAML bị ghim cứng 5.3.1 (hạ cấp từ 6.0.3). price_list.parse gọi yaml.full_load trên file do người dùng upload; với 5.3.1, full_load có thể bị lợi dụng (CVE-2020-14343) để thực thi mã tùy ý. Hàm dễ tổn thương được gọi trực tiếp nên reachable.

**Kịch bản khai thác:** Tài khoản admin bị chiếm (hoặc CSRF) upload file YAML chứa tag python/object/new để thực thi lệnh trên server qua /admin/medicines/import.

**Đề xuất sửa:** Trong app/pyproject.toml đổi pyyaml==5.3.1 thành pyyaml>=6.0.3 (tối thiểu 5.4), bỏ build-constraint setuptools<81 rồi lock lại uv.lock. Trong app/medicare/prescription/price_list.py, hàm parse, thay yaml.full_load bằng yaml.safe_load.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay CSP frame-ancestors; ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware security headers dùng chung cho mọi response: X-Frame-Options: DENY hoặc CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo, kể cả trang /login.

**Đề xuất sửa:** Thêm X-Frame-Options: DENY / CSP frame-ancestors 'none' trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Thêm header Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · LOW · package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) — `app/pyproject.toml:43`

CWE-829 · OWASP A03 · độ tin cậy 0.50 · nguồn: semgrep

**Phân tích:** Khối [tool.uv] mới không đặt exclude-newer (cooldown); gói mới phát hành có thể được kéo vào khi re-lock. Rủi ro thấp vì có uv.lock với hash.

**Đề xuất sửa:** Thêm exclude-newer = "7 days" vào [tool.uv] trong app/pyproject.toml.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo; ảnh hưởng thấp trên /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware security headers chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 59.7 s · 29 lần gọi LLM · 16 lần gọi công cụ · 120880 token vào / 9300 token ra · ≈ $0.1562 · chạm giới hạn: không</sub>
