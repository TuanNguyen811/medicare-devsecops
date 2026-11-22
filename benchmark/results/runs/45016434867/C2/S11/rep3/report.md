<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `bfd2192`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | trivy | CVE-2020-14343 (trivy) | `app/uv.lock:1` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | semgrep | package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) | `app/pyproject.toml:43` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · CVE-2020-14343 (trivy) — `app/uv.lock:1`

CWE-20 · OWASP A03 · vi phạm R-14 · độ tin cậy 0.95 · nguồn: trivy

**Phân tích:** PyYAML 5.3.1 bị ghim cứng (hạ cấp từ 6.0.3) và dính CVE-2020-14343. Hàm bị ảnh hưởng là `yaml.full_load`, và code mới gọi trực tiếp nó trên nội dung file do người dùng tải lên (`/admin/medicines/import`). Lỗ hổng reachable: YAML độc hại có thể dẫn tới thực thi mã tùy ý. Endpoint chỉ cho ADMIN, nhưng tài khoản admin bị chiếm hoặc file bảng giá nhà cung cấp bị giả mạo là đủ để khai thác. `full_load` cũng không cần thiết vì định dạng chỉ gồm dict/list/scalar.

**Kịch bản khai thác:** Kẻ tấn công đưa file bảng giá YAML chứa tag python/object/new để chạy lệnh trên server khi admin tải lên.

**Đề xuất sửa:** Trong app/pyproject.toml, bỏ ghim `pyyaml==5.3.1` và dùng `pyyaml>=6.0.3` (bỏ luôn `build-constraint-dependencies` không còn cần), rồi cập nhật lại uv.lock. Trong price_list.parse, thay `yaml.full_load` bằng `yaml.safe_load`.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy chỗ nào đặt X-Frame-Options hay CSP frame-ancestors, nên ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware đặt header bảo mật toàn cục: `X-Frame-Options: DENY` hoặc CSP `frame-ancestors 'none'`.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Frame-Options hay frame-ancestors nào trong repo; trang /login có thể bị nhúng vào iframe.

**Đề xuất sửa:** Thêm middleware đặt header bảo mật toàn cục: `X-Frame-Options: DENY` hoặc CSP `frame-ancestors 'none'`.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không tìm thấy Content-Security-Policy ở đâu trong repo; ứng dụng chưa có lớp phòng thủ chiều sâu chống XSS.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không tìm thấy Content-Security-Policy ở đâu trong repo.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không tìm thấy Content-Security-Policy ở đâu trong repo.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không tìm thấy Content-Security-Policy ở đâu trong repo.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không tìm thấy Content-Security-Policy ở đâu trong repo.

**Đề xuất sửa:** Thêm CSP chặt (default-src 'self', frame-ancestors 'none') qua middleware toàn cục.

#### 🔴 TP · LOW · package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) — `app/pyproject.toml:43`

CWE-829 · OWASP A03 · độ tin cậy 0.60 · nguồn: semgrep

**Phân tích:** Khối [tool.uv] mới thêm nhưng không đặt `exclude-newer` (dependency cooldown), nên gói mới phát hành, có thể độc hại, được kéo vào ngay. Rủi ro hygiene chuỗi cung ứng, mức thấp.

**Đề xuất sửa:** Thêm `exclude-newer = "7 days"` vào mục [tool.uv] trong app/pyproject.toml.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu cả.

**Đề xuất sửa:** Thêm middleware đặt `X-Content-Type-Options: nosniff` cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu cả, kể cả /health. Rủi ro thấp vì endpoint trả nội dung tối thiểu, nhưng cùng nguyên nhân gốc với các cluster khác.

**Đề xuất sửa:** Thêm middleware đặt `X-Content-Type-Options: nosniff` cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt `X-Content-Type-Options: nosniff` cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 64.1 s · 30 lần gọi LLM · 17 lần gọi công cụ · 154908 token vào / 10327 token ra · ≈ $0.1807 · chạm giới hạn: không</sub>
