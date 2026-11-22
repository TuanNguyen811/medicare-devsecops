<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 3 lỗi thật (TP) · 9 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f029194`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B506 (bandit) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | semgrep | python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | agent | XXE: lxml XMLParser bật resolve_entities khi nhập file XML tải lên | `app/medicare/prescription/legacy_import.py:47` | 0.90 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.40 |

### Chi tiết

#### 🔴 TP · HIGH · B506 (bandit) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Cùng vị trí với F2: Bandit B506 báo `yaml.load` với `yaml.Loader` không an toàn. Dữ liệu là file upload không tin cậy, cho phép khởi tạo đối tượng tùy ý (RCE). Mức LOW của Bandit đánh giá thấp so với tác động thực tế.

**Kịch bản khai thác:** Giống F2: payload `!!python/object/apply` trong file YAML tải lên thực thi mã trên server.

**Đề xuất sửa:** Dùng `yaml.safe_load(data)` trong `_parse_yaml` (legacy_import.py), không dùng `yaml.Loader`.

#### 🔴 TP · HIGH · python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: semgrep

**Phân tích:** `_parse_yaml` gọi `yaml.load(data, Loader=yaml.Loader)` trên nội dung file người dùng tải lên. `yaml.Loader` cho phép dựng đối tượng Python tùy ý (tag `!!python/object/apply:`), dẫn tới thực thi mã từ xa. Route chỉ dành cho ADMIN nên giảm khả năng khai thác, nhưng một tài khoản admin bị chiếm, hoặc admin bị lừa nhập một file "xuất từ HIS cũ", vẫn dẫn tới RCE trên máy chủ chứa dữ liệu bệnh nhân.

**Kịch bản khai thác:** Kẻ tấn công đưa file .yaml chứa `!!python/object/apply:os.system ["..."]` cho admin nhập qua /admin/medicines/import; server thực thi lệnh khi parse.

**Đề xuất sửa:** Trong `_parse_yaml` của app/medicare/prescription/legacy_import.py, thay `yaml.load(..., Loader=yaml.Loader)` bằng `yaml.safe_load(data)`. Định dạng xuất chỉ gồm dict/list/chuỗi/số nên safe_load là đủ.

#### 🔴 TP · HIGH · XXE: lxml XMLParser bật resolve_entities khi nhập file XML tải lên — `app/medicare/prescription/legacy_import.py:47`

CWE-611 · OWASP A02 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** `_parse_xml` tạo `etree.XMLParser(resolve_entities=True)` rồi parse file người dùng tải lên. Comment còn thừa nhận file có DOCTYPE khai báo entity. Kẻ tấn công có thể khai báo external entity `file:///...` (đọc file như biến môi trường chứa SECRET_KEY, mật khẩu DB), và dùng entity lồng nhau (billion laughs) để gây DoS. Nội dung entity được đưa vào trường `ten_thuoc` rồi hiển thị trong danh mục thuốc, nên dữ liệu bị lộ ra. Vi phạm R-14 (không tin đường dẫn/URL từ người dùng) và R-09.

**Kịch bản khai thác:** File XML chứa `<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///proc/self/environ\">]>` và `<ten_thuoc>&e;</ten_thuoc>`; sau khi nhập, nội dung file hiện trong danh mục thuốc.

**Đề xuất sửa:** Trong `_parse_xml` (legacy_import.py) tạo parser với `resolve_entities=False`, `no_network=True`, `load_dtd=False`, `huge_tree=False`; tốt hơn là từ chối file có DOCTYPE hoặc dùng `defusedxml.lxml`. Nếu cần tên có dấu, dùng ký tự UTF-8 hoặc entity số thay vì entity khai báo trong DOCTYPE.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Phát hiện DAST về header chống clickjacking (X-Frame-Options / frame-ancestors) trên GET /. Không liên quan tới code PR này và tôi không có file middleware header để xác nhận; cần kiểm tra cấu hình header toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu header anti-clickjacking trên GET /login. Không nằm trong code PR; cần xem middleware security headers toàn cục mà tôi không có.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /login. Vấn đề cấu hình header toàn cục, không thuộc thay đổi của PR; không đủ bằng chứng trong code đã cung cấp.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt trên POST /appointments. Endpoint không thuộc PR; cần xác nhận middleware header toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt trên endpoint xác nhận lịch hẹn. Không thuộc PR; cần xem cấu hình header toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt trên POST /patients. Không thuộc PR; cần xem cấu hình header toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt trên POST /patients/{patient_id}/edit. Không thuộc PR; cần xem cấu hình header toàn cục.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /. Cấu hình header toàn cục, không thuộc PR; không có file để xác nhận.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /health. Cấu hình header toàn cục, không thuộc PR; không có bằng chứng trong code đã cung cấp.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 37.9 s · 14 lần gọi LLM · 13 lần gọi công cụ · 102264 token vào / 5554 token ra · ≈ $0.2692 · chạm giới hạn: không</sub>
