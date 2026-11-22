<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 3 lỗi thật (TP) · 10 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `bfd2192`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | trivy | CVE-2020-14343 (trivy) | `app/uv.lock:1` | 0.95 |
| 🔴 TP | HIGH | agent | Giải tuần tự không an toàn: yaml.full_load trên file admin tải lên | `app/medicare/prescription/price_list.py:40` | 0.90 |
| 🔴 TP | LOW | semgrep | package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) | `app/pyproject.toml:43` | 0.60 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.30 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.30 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.30 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.30 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.30 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.30 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.30 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.30 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.30 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.30 |

### Chi tiết

#### 🔴 TP · CRITICAL · CVE-2020-14343 (trivy) — `app/uv.lock:1`

CWE-502 · OWASP A03 · độ tin cậy 0.95 · nguồn: trivy

**Phân tích:** PR hạ cấp pyyaml từ 6.0.3 xuống 5.3.1 (dính CVE-2020-14343). Lỗ hổng nằm ở chính hàm `yaml.full_load`, mà `price_list.parse` gọi trực tiếp trên nội dung file do người dùng tải lên. Vì vậy hàm bị lỗi có thể được gọi tới (reachable). Kẻ tấn công có thể dựng payload `!!python/object/new` để chạy mã tùy ý trên server. Chỉ ADMIN được upload, nhưng tài khoản admin bị chiếm hoặc bị lừa tải file vẫn dẫn tới RCE. Comment "Same PyYAML as the pharmacy stock system" không phải lý do chính đáng để ghim phiên bản có lỗ hổng.

**Kịch bản khai thác:** Kẻ tấn công có quyền ADMIN (hoặc lừa admin tải file) gửi file YAML chứa tag python/object/new tới /admin/medicines/import. `yaml.full_load` của PyYAML 5.3.1 dựng đối tượng và chạy lệnh trên server, lộ dữ liệu bệnh nhân.

**Đề xuất sửa:** Trong app/pyproject.toml bỏ ghim `pyyaml==5.3.1`, dùng `pyyaml>=6.0.3` (tối thiểu 5.4) rồi cập nhật lại uv.lock và bỏ `build-constraint-dependencies`. Trong price_list.parse đổi `yaml.full_load` thành `yaml.safe_load`. Giữ các bước kiểm tra kiểu đã có trong `_line`.

#### 🔴 TP · HIGH · Giải tuần tự không an toàn: yaml.full_load trên file admin tải lên — `app/medicare/prescription/price_list.py:40`

CWE-502 · OWASP A08 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** `price_list.parse` dùng `yaml.full_load` cho nội dung file upload. Hàm này không an toàn với dữ liệu không tin cậy, và với PyYAML 5.3.1 cho phép thực thi mã (CVE-2020-14343). Dữ liệu chỉ cần là cấu trúc đơn giản (dict/list/int/str) nên `safe_load` là đủ.

**Kịch bản khai thác:** File YAML độc hại với tag `!!python/object/new:` được tải lên /admin/medicines/import và chạy lệnh hệ thống khi parse.

**Đề xuất sửa:** Trong price_list.parse thay `yaml.full_load` bằng `yaml.safe_load`, đồng thời nâng pyyaml lên bản >=6.0.3.

#### 🔴 TP · LOW · package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) — `app/pyproject.toml:43`

CWE-829 · OWASP A03 · độ tin cậy 0.60 · nguồn: semgrep

**Phân tích:** Mục `[tool.uv]` được thêm mà không đặt `exclude-newer` (cooldown). Phụ thuộc mới có thể được resolve ngay khi vừa phát hành. uv.lock đã ghim hash nên rủi ro thấp, nhưng đây là khuyến nghị chuỗi cung ứng hợp lý.

**Kịch bản khai thác:** Gói độc hại mới phát hành được resolve vào lần `uv lock` tiếp theo trước khi cộng đồng phát hiện.

**Đề xuất sửa:** Thêm `exclude-newer = "7 days"` vào mục [tool.uv] trong app/pyproject.toml. Nếu bỏ ghim pyyaml 5.3.1 thì xóa luôn build-constraint-dependencies vì không còn cần build từ source.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Phát hiện DAST về header chống clickjacking trên GET /. Code của PR không đụng tới middleware header bảo mật, và tôi không có file để xác minh có middleware set header hay không. Không đủ bằng chứng để kết luận.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu header chống clickjacking trên GET /login. Không liên quan code của PR; không có bằng chứng về cấu hình header của ứng dụng trong những gì tôi đã đọc.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /login. Cần kiểm tra middleware thêm header; không có trong diff PR nên không thể xác nhận.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /appointments. Là cấu hình toàn ứng dụng, ngoài phạm vi code PR; không đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu CSP trên route cancel lịch hẹn. Cấu hình header toàn cục, không nằm trong code PR; không đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu CSP trên route confirm lịch hẹn. Cấu hình header toàn cục, không nằm trong code PR; không đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu CSP trên POST /patients. Cấu hình header toàn cục, không nằm trong code PR; không đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu CSP trên route sửa bệnh nhân. Cấu hình header toàn cục, không nằm trong code PR; không đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên GET /. Không liên quan code PR; cần xem middleware header của ứng dụng.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.30 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health. Mức thấp, không liên quan code PR; cần xem middleware header của ứng dụng.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 41.6 s · 3 lần gọi LLM · 16 lần gọi công cụ · 94274 token vào / 6500 token ra · ≈ $0.2634 · chạm giới hạn: không</sub>
