<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 3 lỗi cần sửa (1 do Agent tự tìm, công cụ quét không báo)

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `c52e3a9`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | B506 (bandit) | `app/medicare/prescription/legacy_import.py:40` | bandit | 0.95 |
| 🔴 TP | HIGH | python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) | `app/medicare/prescription/legacy_import.py:40` | semgrep | 0.95 |
| 🔴 TP | HIGH | XXE: lxml XMLParser bật resolve_entities khi parse file upload | `app/medicare/prescription/legacy_import.py:49` | agent | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · B506 (bandit) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Cùng vị trí với F2: yaml.load với yaml.Loader trên dữ liệu upload cho phép khởi tạo đối tượng tùy ý dẫn tới RCE. Bandit chấm LOW nhưng thực tế mức HIGH.

**Đề xuất sửa:** Dùng yaml.safe_load trong legacy_import._parse_yaml.

#### 🔴 TP · HIGH · python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: semgrep

**Phân tích:** _parse_yaml dùng yaml.load với yaml.Loader trên nội dung file do người dùng upload. Loader này cho phép tag python/object/apply nên có thể thực thi mã tùy ý (RCE). Chỉ ADMIN truy cập được, nhưng tài khoản admin bị chiếm hoặc bị lừa upload vẫn dẫn tới RCE trên server.

**Kịch bản khai thác:** File .yaml chứa tag !!python/object/apply:os.system với lệnh tùy ý, upload tại /admin/medicines/import, sẽ chạy lệnh trên server.

**Đề xuất sửa:** Trong legacy_import._parse_yaml, thay yaml.load(..., Loader=yaml.Loader) bằng yaml.safe_load (hoặc Loader=yaml.SafeLoader). Giữ nguyên bước kiểm tra kiểu dữ liệu phía sau.

#### 🔴 TP · HIGH · XXE: lxml XMLParser bật resolve_entities khi parse file upload — `app/medicare/prescription/legacy_import.py:49`

CWE-611 · OWASP A02 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** _parse_xml dùng etree.XMLParser(resolve_entities=True) trên XML do người dùng upload, không tắt network. Kẻ tấn công có thể khai báo external entity (file:///etc/passwd, SSRF) hoặc billion laughs; nội dung entity được đọc vào ten_thuoc/don_vi và hiện lại qua danh mục thuốc hoặc thông báo lỗi.

**Kịch bản khai thác:** Upload XML có DOCTYPE khai báo ENTITY x SYSTEM "file:///etc/passwd" và dùng &x; trong ten_thuoc; nội dung file server được lưu vào danh mục thuốc và hiển thị.

**Đề xuất sửa:** Trong legacy_import._parse_xml, tạo XMLParser với resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False (hoặc dùng defusedxml.lxml). Từ chối tài liệu có DOCTYPE; nếu cần ký tự có dấu thì dùng mã hóa UTF-8 thay vì entity.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Tìm toàn repo không thấy X-Frame-Options hay frame-ancestors; ứng dụng không đặt header chống clickjacking. | Thêm middleware chung đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Repo không đặt Content-Security-Policy. | Middleware chung đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none'). |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu X-Content-Type-Options trên mọi response. | Middleware chung thêm X-Content-Type-Options: nosniff. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Repo không đặt X-Content-Type-Options: nosniff ở bất kỳ đâu. | Middleware chung thêm X-Content-Type-Options: nosniff. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 67.1 s · 31 lần gọi LLM · 17 lần gọi công cụ · 166816 token vào / 11315 token ra · ≈ $0.2566 · chạm giới hạn: không</sub>
