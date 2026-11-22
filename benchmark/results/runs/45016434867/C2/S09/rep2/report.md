<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `447aa04`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | bandit | B310 (bandit) | `app/medicare/record/lab.py:39` | 0.90 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |

### Chi tiết

#### 🔴 TP · HIGH · B310 (bandit) — `app/medicare/record/lab.py:39`

CWE-918 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** download() chỉ kiểm tra scheme http/https và có hostname, không có allowlist host (vi phạm R-14). urlopen còn tự theo redirect. Bác sĩ có thể khiến server gọi tới địa chỉ nội bộ (localhost, 169.254.169.254, dịch vụ nội bộ) → SSRF. Thông báo lỗi khác nhau cho phép dò cổng/host nội bộ; nếu dịch vụ nội bộ trả PDF/ảnh thì nội dung được lưu và tải về được.

**Kịch bản khai thác:** Bác sĩ nhập url=http://169.254.169.254/... hoặc http://10.0.0.5:8080/x.pdf; server gọi từ mạng nội bộ, phản hồi lỗi cho biết host/cổng tồn tại; URL redirect tới PDF nội bộ sẽ được lưu và đọc được.

**Đề xuất sửa:** Trong lab.download(): đối chiếu hostname với allowlist cấu hình (host của LIS, ví dụ lis.medicare.local) và bắt buộc https. Phân giải DNS và chặn IP loopback/private/link-local. Tắt tự động redirect (opener với HTTPRedirectHandler tùy chỉnh) hoặc kiểm tra lại allowlist ở mỗi bước redirect. Dùng thông báo lỗi chung.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay CSP frame-ancestors trong ứng dụng (main.py chỉ có Session, CatchAllErrors, Metrics middleware). Thiếu chống clickjacking toàn cục.

**Đề xuất sửa:** Thêm một middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options toàn cục cho GET /.

**Đề xuất sửa:** Thêm security-headers middleware trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options toàn cục, /health cũng thiếu; tác động thấp.

**Đề xuất sửa:** Thêm security-headers middleware trong main.py.

#### 🔴 TP · LOW · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking toàn ứng dụng; trang /login bị ảnh hưởng.

**Đề xuất sửa:** Thêm security-headers middleware trong app/medicare/main.py (X-Frame-Options DENY, CSP frame-ancestors 'none').

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Chỉ route download_lab_result đặt nosniff; các response khác không có X-Content-Type-Options và không có middleware chung.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm security-headers middleware trong main.py đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong mã.

**Đề xuất sửa:** Thêm CSP (default-src 'self', frame-ancestors 'none') qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong mã.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong mã.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong mã.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong mã.

**Đề xuất sửa:** Thêm CSP qua middleware chung trong main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 60.1 s · 27 lần gọi LLM · 15 lần gọi công cụ · 142232 token vào / 8991 token ra · ≈ $0.1602 · chạm giới hạn: không</sub>
