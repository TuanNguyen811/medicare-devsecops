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
| 🔴 TP | LOW | semgrep | package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) | `app/pyproject.toml:43` | 0.50 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · CRITICAL · CVE-2020-14343 (trivy) — `app/uv.lock:1`

CWE-502 · OWASP A03 · độ tin cậy 0.95 · nguồn: trivy

**Phân tích:** PyYAML 5.3.1 bị ghim cứng và được import trong price_list.py. parse() gọi yaml.full_load(content) trên nội dung file do người dùng tải lên. Trong 5.3.1, full_load vẫn cho phép dựng đối tượng Python tùy ý (CVE-2020-14343), dẫn tới thực thi mã từ xa. Hàm dễ bị tấn công được gọi trực tiếp, nên lỗi này tới được. Tuy endpoint chỉ dành cho ADMIN, một tài khoản admin bị chiếm hoặc một file bảng giá của nhà cung cấp bị giả mạo vẫn đủ để chiếm server.

**Kịch bản khai thác:** Admin (hoặc kẻ lừa admin) tải lên file .yaml chứa tag !!python/object/new:... để chạy lệnh hệ thống trên server khi gọi full_load.

**Đề xuất sửa:** Trong price_list.parse() đổi yaml.full_load thành yaml.safe_load. Nâng pyyaml lên >=5.4 (nên dùng bản 6.x hiện tại) trong app/pyproject.toml, bỏ ghim ==5.3.1 và bỏ build-constraint setuptools<81, rồi chạy lại uv lock. Wheel của 6.x đã có cho Python 3.12.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** search_code không tìm thấy X-Frame-Options hay Content-Security-Policy ở bất kỳ đâu trong ứng dụng, nên phản hồi không có header chống clickjacking.

**Đề xuất sửa:** Thêm middleware đặt header bảo mật cho mọi phản hồi, gồm X-Frame-Options: DENY hoặc CSP frame-ancestors 'none', X-Content-Type-Options: nosniff và Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong ứng dụng, trang /login có thể bị nhúng vào iframe.

**Đề xuất sửa:** Thêm middleware đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt X-Content-Type-Options hay CSP ở chỗ nào (search_code không có kết quả).

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff và CSP trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self') trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật dùng chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt Content-Security-Policy ở bất kỳ đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy trong middleware header bảo mật dùng chung.

#### 🔴 TP · LOW · package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) — `app/pyproject.toml:43`

CWE-829 · OWASP A03 · độ tin cậy 0.50 · nguồn: semgrep

**Phân tích:** Mục [tool.uv] mới được thêm vào nhưng chưa đặt exclude-newer (cooldown). Đây là gia cố chuỗi cung ứng, rủi ro thấp vì uv.lock đã ghim hash.

**Đề xuất sửa:** Trong mục [tool.uv] của app/pyproject.toml thêm exclude-newer với khoảng cooldown, ví dụ 7 ngày.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt X-Content-Type-Options ở bất kỳ đâu.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật dùng chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt X-Content-Type-Options ở bất kỳ đâu, kể cả với /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật dùng chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 40.8 s · 16 lần gọi LLM · 15 lần gọi công cụ · 82359 token vào / 5536 token ra · ≈ $0.1400 · chạm giới hạn: không</sub>
