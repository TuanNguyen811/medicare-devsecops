<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f029194`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B506 (bandit) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | semgrep | python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | agent | XXE trong nhập danh mục thuốc XML (resolve_entities=True) | `app/medicare/prescription/legacy_import.py:49` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |

### Chi tiết

#### 🔴 TP · HIGH · B506 (bandit) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Cùng vị trí với F2: yaml.Loader không an toàn trên dữ liệu upload, dẫn tới RCE.

**Đề xuất sửa:** Dùng yaml.safe_load trong legacy_import._parse_yaml.

#### 🔴 TP · HIGH · python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: semgrep

**Phân tích:** yaml.load với yaml.Loader (không an toàn) được áp dụng trực tiếp lên file người dùng tải lên qua POST /admin/medicines/import. Tag như !!python/object/apply:os.system cho phép thực thi mã tùy ý (RCE) trên server.

**Kịch bản khai thác:** File .yaml chứa "!!python/object/apply:os.system ['cmd']" được tải lên và lệnh chạy trên server.

**Đề xuất sửa:** Trong legacy_import._parse_yaml thay bằng yaml.safe_load (hoặc Loader=yaml.SafeLoader).

#### 🔴 TP · HIGH · XXE trong nhập danh mục thuốc XML (resolve_entities=True) — `app/medicare/prescription/legacy_import.py:49`

CWE-611 · OWASP A02 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** _parse_xml tạo etree.XMLParser(resolve_entities=True) và parse file do admin tải lên. Entity ngoại (SYSTEM "file:///...") được resolve; nội dung đọc được đưa vào trường ten_thuoc/don_vi, sau đó lưu DB, hiển thị trong danh mục hoặc lộ qua thông báo lỗi. Cũng cho phép SSRF và entity expansion (billion laughs) gây DoS.

**Kịch bản khai thác:** Kẻ tấn công kiểm soát tài khoản admin (hoặc lừa admin tải file) gửi XML có DOCTYPE khai báo entity SYSTEM "file:///etc/passwd" và dùng &x; trong ten_thuoc. Nội dung file được lưu thành tên thuốc và hiển thị ở /admin/medicines.

**Đề xuất sửa:** Trong legacy_import._parse_xml dùng etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False, huge_tree=False), hoặc dùng defusedxml.lxml; từ chối file có DOCTYPE/ENTITY. Chuyển các tên có dấu sang ký tự UTF-8 trực tiếp thay vì entity.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy cấu hình X-Frame-Options hay frame-ancestors, nên ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có header chống clickjacking trong repo (trang /login).

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Repo không có Content-Security-Policy.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trong toàn ứng dụng.

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health do không có middleware header bảo mật.

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options: nosniff ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 48.4 s · 16 lần gọi LLM · 15 lần gọi công cụ · 96134 token vào / 5465 token ra · ≈ $0.0915 · chạm giới hạn: không</sub>
