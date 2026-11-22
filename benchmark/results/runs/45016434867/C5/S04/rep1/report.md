<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f029194`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B506 (bandit) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | semgrep | python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) | `app/medicare/prescription/legacy_import.py:40` | 0.97 |
| 🔴 TP | HIGH | agent | XXE: lxml XMLParser bật resolve_entities=True trên file upload | `app/medicare/prescription/legacy_import.py:49` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · B506 (bandit) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Trùng với F2: `yaml.Loader` không an toàn trên dữ liệu upload, cho phép khởi tạo đối tượng tùy ý (RCE). Mức LOW của Bandit đánh giá thấp.

**Đề xuất sửa:** Dùng `yaml.safe_load` trong `_parse_yaml` (legacy_import.py).

#### 🔴 TP · HIGH · python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · vi phạm R-14 · độ tin cậy 0.97 · nguồn: semgrep

**Phân tích:** `_parse_yaml` dùng `yaml.load(data, Loader=yaml.Loader)` trên file do người dùng upload. Loader này cho phép tạo đối tượng Python tùy ý (`!!python/object/apply:os.system`), dẫn tới RCE. Dù route chỉ dành cho admin, đây vẫn là deserialization không an toàn; tài khoản admin bị chiếm hoặc CSRF/social engineering đều dẫn tới RCE.

**Kịch bản khai thác:** Upload file .yaml chứa `!!python/object/apply:os.system ["..."]` tới /admin/medicines/import, server thực thi lệnh.

**Đề xuất sửa:** Trong app/medicare/prescription/legacy_import.py, hàm `_parse_yaml`, thay `yaml.load(..., Loader=yaml.Loader)` bằng `yaml.safe_load(data)`. Format xuất chỉ gồm dict/list/scalar nên không cần loader đầy đủ.

#### 🔴 TP · HIGH · XXE: lxml XMLParser bật resolve_entities=True trên file upload — `app/medicare/prescription/legacy_import.py:49`

CWE-611 · OWASP A05 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** `_parse_xml` tạo `etree.XMLParser(resolve_entities=True)` để phân tích XML do người dùng upload. Kẻ tấn công khai báo external entity trong DOCTYPE (`file:///etc/passwd`, SSRF) và nội dung được đọc vào trường như `ten_thuoc`, sau đó hiển thị trong danh mục thuốc/thông báo lỗi. Ngoài ra có nguy cơ billion laughs.

**Kịch bản khai thác:** Upload XML có `<!ENTITY x SYSTEM "file:///etc/passwd">` và `<ten_thuoc>&x;</ten_thuoc>`; nội dung file được lưu thành tên thuốc và hiển thị trên /admin/medicines.

**Đề xuất sửa:** Trong `_parse_xml` (legacy_import.py) dùng `etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False, huge_tree=False)`, hoặc từ chối file có DOCTYPE/ENTITY. Nếu cần entity chữ có dấu thì chuyển export sang UTF-8 thay vì entity.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm trong repo không có X-Frame-Options, CSP hay X-Content-Type-Options; main.py chỉ có middleware lỗi/session/metrics. Thiếu header là thật, áp dụng toàn ứng dụng (không do PR này gây ra).

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt `X-Frame-Options: DENY` (hoặc CSP `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff` và `Content-Security-Policy` cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking ở bất kỳ đâu trong ứng dụng (đã search), trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Thêm middleware đặt `X-Frame-Options: DENY` / CSP `frame-ancestors 'none'` trong app/medicare/main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có `X-Content-Type-Options` trong code; header thiếu toàn ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware trong main.py đặt `X-Content-Type-Options: nosniff` cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở đâu trong app.

**Đề xuất sửa:** Thêm header `Content-Security-Policy` chặt chẽ qua middleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở đâu trong app.

**Đề xuất sửa:** Thêm header `Content-Security-Policy` qua middleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở đâu trong app.

**Đề xuất sửa:** Thêm header `Content-Security-Policy` qua middleware trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở đâu trong app.

**Đề xuất sửa:** Thêm header `Content-Security-Policy` qua middleware trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có `X-Content-Type-Options` trong code.

**Đề xuất sửa:** Middleware main.py đặt `X-Content-Type-Options: nosniff`.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có `X-Content-Type-Options` trong code.

**Đề xuất sửa:** Middleware main.py đặt `X-Content-Type-Options: nosniff`.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 37.3 s · 17 lần gọi LLM · 16 lần gọi công cụ · 116393 token vào / 5661 token ra · ≈ $0.1599 · chạm giới hạn: không</sub>
