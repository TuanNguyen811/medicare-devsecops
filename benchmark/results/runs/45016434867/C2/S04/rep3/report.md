<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f029194`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B506 (bandit) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | semgrep | python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) | `app/medicare/prescription/legacy_import.py:40` | 0.97 |
| 🔴 TP | HIGH | agent | XXE: lxml XMLParser bật resolve_entities khi nhập file XML | `app/medicare/prescription/legacy_import.py:49` | 0.90 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |

### Chi tiết

#### 🔴 TP · HIGH · B506 (bandit) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Cùng vị trí với F2: `yaml.load` với `yaml.Loader` trên dữ liệu upload, cho phép tạo object tùy ý (RCE). Bandit đánh LOW nhưng thực tế nghiêm trọng hơn.

**Đề xuất sửa:** Dùng `yaml.safe_load` trong `_parse_yaml` của legacy_import.py.

#### 🔴 TP · HIGH · python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** `_parse_yaml` gọi `yaml.load(data, Loader=yaml.Loader)` trên nội dung file do người dùng upload. `yaml.Loader` cho phép tag `!!python/object/apply:...`, dẫn tới thực thi mã tùy ý trên server. Route chỉ cho ADMIN, nhưng tài khoản admin bị chiếm hoặc CSRF/social engineering vẫn dẫn tới RCE.

**Kịch bản khai thác:** Upload file .yaml chứa `!!python/object/apply:os.system ["..."]` để chạy lệnh trên server.

**Đề xuất sửa:** Trong `_parse_yaml` (legacy_import.py) dùng `yaml.safe_load` (hoặc `yaml.SafeLoader`) thay cho `yaml.Loader`. Dữ liệu import chỉ gồm dict/list/scalar nên đủ dùng.

#### 🔴 TP · HIGH · XXE: lxml XMLParser bật resolve_entities khi nhập file XML — `app/medicare/prescription/legacy_import.py:49`

CWE-611 · OWASP A02 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** `_parse_xml` dùng `etree.XMLParser(resolve_entities=True)` trên XML do người dùng upload, không tắt `no_network`, không chặn DTD. Kẻ tấn công có thể khai báo external entity `file:///etc/passwd` và nội dung được đưa vào trường ten_thuoc/don_vi, sau đó hiển thị ở danh mục thuốc hoặc trong thông báo lỗi (đọc file); cũng có thể SSRF và billion laughs (DoS).

**Kịch bản khai thác:** File XML có DOCTYPE với `<!ENTITY x SYSTEM \"file:///etc/passwd\">` và `<ten_thuoc>&x;</ten_thuoc>`; nội dung file bị lưu vào danh mục thuốc và hiển thị.

**Đề xuất sửa:** Trong `_parse_xml` tạo parser với `resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False`, và từ chối tài liệu có DOCTYPE; hoặc dùng `defusedxml.lxml`. Nếu cần ký tự có dấu, yêu cầu UTF-8 thay vì entity.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy chỗ nào đặt X-Frame-Options hay CSP frame-ancestors, nên thiếu header chống clickjacking là thật (cấu hình toàn ứng dụng, không do PR này gây ra).

**Đề xuất sửa:** Thêm middleware trong app factory đặt `X-Frame-Options: DENY` và CSP `frame-ancestors 'none'` cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu `nosniff`, không có header nào được đặt trong code.

**Đề xuất sửa:** Thêm `X-Content-Type-Options: nosniff` trong middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Endpoint /health cũng thiếu `nosniff`; tác động thấp vì trả JSON nhỏ.

**Đề xuất sửa:** Middleware chung đặt `X-Content-Type-Options: nosniff` cho mọi response.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login không có X-Frame-Options/frame-ancestors; repo không đặt header nào.

**Đề xuất sửa:** Dùng chung middleware security headers: `X-Frame-Options: DENY` và CSP `frame-ancestors 'none'`.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt `X-Content-Type-Options: nosniff` ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm `X-Content-Type-Options: nosniff` trong middleware security headers.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong code ứng dụng.

**Đề xuất sửa:** Thêm CSP (default-src 'self', frame-ancestors 'none') trong middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong code ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong code ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong code ứng dụng.

**Đề xuất sửa:** Thêm CSP trong middleware chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 36.4 s · 16 lần gọi LLM · 15 lần gọi công cụ · 94880 token vào / 5593 token ra · ≈ $0.0911 · chạm giới hạn: không</sub>
