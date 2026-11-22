<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f029194`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B506 (bandit) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | semgrep | python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | agent | XXE: lxml XMLParser resolve_entities=True khi nhập file XML | `app/medicare/prescription/legacy_import.py:49` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · B506 (bandit) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Trùng với F2: yaml.Loader không an toàn với dữ liệu upload, cho phép khởi tạo đối tượng tùy ý.

**Đề xuất sửa:** Dùng yaml.safe_load trong legacy_import._parse_yaml.

#### 🔴 TP · HIGH · python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: semgrep

**Phân tích:** _parse_yaml dùng yaml.load(data, Loader=yaml.Loader) trên file do người dùng tải lên. Loader này cho phép tạo đối tượng Python tùy ý (tag !!python/object/apply), dẫn tới thực thi mã từ xa. Route chỉ cho ADMIN nhưng tài khoản admin bị chiếm hoặc CSRF vẫn dẫn tới RCE trên server.

**Kịch bản khai thác:** Upload file .yaml chứa `!!python/object/apply:os.system ["..."]` thì server chạy lệnh tùy ý.

**Đề xuất sửa:** Trong legacy_import._parse_yaml dùng yaml.safe_load (hoặc Loader=yaml.SafeLoader) thay cho yaml.Loader; giữ kiểm tra kiểu dict/list sau đó.

#### 🔴 TP · HIGH · XXE: lxml XMLParser resolve_entities=True khi nhập file XML — `app/medicare/prescription/legacy_import.py:49`

CWE-611 · OWASP A02 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** _parse_xml bật resolve_entities=True trên XML do người dùng tải lên, cho phép thực thể ngoài (file:///etc/passwd, URL nội bộ/SSRF) và billion laughs. Nội dung thực thể có thể đi vào ten_thuoc rồi lưu DB và hiển thị.

**Kịch bản khai thác:** Admin upload XML có DOCTYPE khai báo ENTITY x SYSTEM "file:///etc/passwd" và dùng &x; trong ten_thuoc; nội dung file xuất hiện trong danh mục thuốc.

**Đề xuất sửa:** Trong legacy_import._parse_xml tạo etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False, huge_tree=False) hoặc dùng defusedxml; từ chối tài liệu có DOCTYPE/ENTITY.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options hay CSP frame-ancestors được đặt, nên toàn bộ phản hồi thiếu chống clickjacking.

**Đề xuất sửa:** Thêm middleware đặt security headers cho mọi response: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login bị ảnh hưởng.

**Đề xuất sửa:** Middleware đặt X-Frame-Options: DENY / CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy.

**Đề xuất sửa:** Middleware thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy.

**Đề xuất sửa:** Middleware thêm Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy.

**Đề xuất sửa:** Middleware thêm Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy.

**Đề xuất sửa:** Middleware thêm Content-Security-Policy cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn app.

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health, cùng nguyên nhân thiếu middleware.

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 64.1 s · 28 lần gọi LLM · 15 lần gọi công cụ · 139086 token vào / 9927 token ra · ≈ $0.2318 · chạm giới hạn: không</sub>
