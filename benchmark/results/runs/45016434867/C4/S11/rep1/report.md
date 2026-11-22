<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `bfd2192`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | trivy | CVE-2020-14343 (trivy) | `app/uv.lock:1` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | semgrep | package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) | `app/pyproject.toml:43` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · CVE-2020-14343 (trivy) — `app/uv.lock:1`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: trivy

**Phân tích:** PR hạ cấp PyYAML từ 6.0.3 xuống 5.3.1 (CVE-2020-14343). Gói được import và đi vào code path bị ảnh hưởng: price_list.parse gọi yaml.full_load(content) trên file do người dùng upload. Với 5.3.1, full_load cho phép dựng đối tượng Python tùy ý, dẫn tới RCE. Endpoint /admin/medicines/import chỉ cho admin, nhưng tài khoản admin bị chiếm hoặc file độc hại từ nhà cung cấp vẫn có thể thực thi mã.

**Kịch bản khai thác:** Kẻ tấn công đưa file YAML chứa tag python/object/new cho admin nhập bảng giá; yaml.full_load thực thi lệnh trên server.

**Đề xuất sửa:** Trong app/pyproject.toml bỏ ràng buộc pyyaml==5.3.1, dùng pyyaml>=6.0.3 (bỏ build-constraint setuptools<81 vì không còn cần) và cập nhật uv.lock. Trong app/medicare/prescription/price_list.py, hàm parse, thay yaml.full_load bằng yaml.safe_load.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** search_code không thấy nơi nào đặt X-Frame-Options hay CSP frame-ancestors; ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware toàn cục (app/medicare/common) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có middleware đặt header chống clickjacking; trang /login bị ảnh hưởng.

**Đề xuất sửa:** Dùng middleware security-headers toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không tìm thấy X-Content-Type-Options/CSP trong code; response thiếu header.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff và Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở đâu (search_code rỗng).

**Đề xuất sửa:** Middleware toàn cục thêm header Content-Security-Policy chặt (default-src 'self').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng (search_code rỗng).

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng (search_code rỗng).

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng (search_code rỗng).

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu CSP toàn ứng dụng (search_code rỗng).

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy.

#### 🔴 TP · LOW · package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) — `app/pyproject.toml:43`

CWE-829 · OWASP A03 · độ tin cậy 0.60 · nguồn: semgrep

**Phân tích:** Khối [tool.uv] mới trong PR không đặt exclude-newer (cooldown). Rủi ro thấp vì uv.lock có hash, nhưng khi cập nhật lock nên có cooldown.

**Đề xuất sửa:** Thêm exclude-newer = "7 days" vào mục [tool.uv] trong app/pyproject.toml.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có code đặt X-Content-Type-Options (search_code rỗng).

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có code đặt X-Content-Type-Options (search_code rỗng).

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 58.0 s · 29 lần gọi LLM · 16 lần gọi công cụ · 106997 token vào / 9759 token ra · ≈ $0.2026 · chạm giới hạn: không</sub>
