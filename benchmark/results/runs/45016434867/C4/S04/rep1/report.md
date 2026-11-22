<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 3 lỗi thật (TP) · 9 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f029194`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B506 (bandit) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | semgrep | python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) | `app/medicare/prescription/legacy_import.py:40` | 0.95 |
| 🔴 TP | HIGH | agent | XXE: lxml XMLParser với resolve_entities=True trên file admin upload | `app/medicare/prescription/legacy_import.py:49` | 0.90 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.50 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.50 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.50 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |

### Chi tiết

#### 🔴 TP · HIGH · B506 (bandit) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: bandit

**Phân tích:** Cùng vị trí với F2: yaml.Loader không an toàn trên dữ liệu upload, thực chất là RCE.

**Đề xuất sửa:** Dùng yaml.safe_load trong _parse_yaml.

#### 🔴 TP · HIGH · python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load (semgrep) — `app/medicare/prescription/legacy_import.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.95 · nguồn: semgrep

**Phân tích:** yaml.load với yaml.Loader cho phép tạo đối tượng Python tùy ý (!!python/object/apply) từ file upload → RCE.

**Kịch bản khai thác:** Upload file .yaml chứa !!python/object/apply:os.system ["..."] thực thi lệnh trên server.

**Đề xuất sửa:** Trong _parse_yaml dùng yaml.safe_load (hoặc Loader=yaml.SafeLoader).

#### 🔴 TP · HIGH · XXE: lxml XMLParser với resolve_entities=True trên file admin upload — `app/medicare/prescription/legacy_import.py:49`

CWE-611 · OWASP A02 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** _parse_xml bật resolve_entities=True và không tắt no_network/load_dtd, nên DOCTYPE do người upload kiểm soát có thể khai báo external entity (file:///etc/passwd, URL nội bộ) hoặc entity bùng nổ (billion laughs). Nội dung entity được đưa vào ten_thuoc/don_vi và lưu DB, hiển thị lại trong lỗi/danh mục, nên có thể đọc dữ liệu.

**Kịch bản khai thác:** Admin (hoặc kẻ có CSRF/tài khoản admin bị chiếm) upload XML có DOCTYPE với &lt;!ENTITY x SYSTEM "file:///etc/passwd"&gt; đặt trong &lt;ten_thuoc&gt;&amp;x;&lt;/ten_thuoc&gt;; nội dung file được lưu vào danh mục thuốc và hiển thị.

**Đề xuất sửa:** Trong _parse_xml dùng etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False, huge_tree=False), hoặc dùng defusedxml.lxml. Từ chối tài liệu có DOCTYPE; nếu cần ký tự có dấu thì dùng UTF-8 trực tiếp thay vì entity.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Không tìm thấy middleware đặt X-Frame-Options/CSP/X-Content-Type-Options trong repo, nên cảnh báo có vẻ đúng, nhưng là vấn đề cấu hình toàn cục (có thể do reverse proxy), không thuộc code của PR này.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F3: không thấy header chống clickjacking trong code; có thể đặt ở proxy, ngoài phạm vi PR.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Không thấy header bảo mật trong code; cấu hình toàn cục ngoài phạm vi PR.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Không thấy CSP trong code; có thể ở proxy, ngoài phạm vi PR.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F8.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F8.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F8.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F7.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Như F7.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 31.7 s · 16 lần gọi LLM · 15 lần gọi công cụ · 77664 token vào / 4644 token ra · ≈ $0.1248 · chạm giới hạn: không</sub>
