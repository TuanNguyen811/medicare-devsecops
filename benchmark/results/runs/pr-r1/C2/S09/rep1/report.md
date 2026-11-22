<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 2 lỗi cần sửa

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `7a6f86d`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | py/full-ssrf (codeql) | `app/medicare/record/lab.py:37` | codeql | 0.95 |
| 🔴 TP | MEDIUM | B310 (bandit) | `app/medicare/record/lab.py:39` | bandit | 0.70 |

### Chi tiết

#### 🔴 TP · HIGH · py/full-ssrf (codeql) — `app/medicare/record/lab.py:37`

CWE-918 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.95 · nguồn: codeql

**Phân tích:** download() chỉ kiểm tra scheme http/https và có hostname, rồi gọi urllib.request.urlopen với URL do bác sĩ nhập. Không có allowlist host (vi phạm R-14), không chặn IP loopback/private/link-local (169.254.169.254, mạng nội bộ), và urlopen tự theo redirect nên có thể bị chuyển hướng tới địa chỉ nội bộ. Dù có lọc content-type, request vẫn được gửi (blind SSRF, dò cổng/dịch vụ nội bộ qua thông báo lỗi khác nhau); nếu dịch vụ nội bộ trả PDF/ảnh thì nội dung được lưu và đọc lại qua /lab-results/{id}.

**Kịch bản khai thác:** Bác sĩ phụ trách (hoặc tài khoản bị chiếm) gửi url=http://10.0.0.5:8080/x hoặc URL của kẻ tấn công trả redirect 302 tới dịch vụ nội bộ/metadata cloud; server gửi request từ mạng nội bộ. Thông báo lỗi "Không tải được" so với "Kết quả phải là file PDF" cho phép dò dịch vụ nội bộ.

**Đề xuất sửa:** Trong app/medicare/record/lab.py::download, đối chiếu host của URL với allowlist host LIS lấy từ cấu hình (biến môi trường, ví dụ lis.medicare.local) và chỉ cho phép https. Phân giải DNS và từ chối IP loopback/private/link-local. Tắt theo redirect (opener tùy biến với redirect handler từ chối) hoặc kiểm tra lại allowlist ở mỗi redirect. Dùng thông báo lỗi chung để không lộ trạng thái dịch vụ nội bộ.

#### 🔴 TP · MEDIUM · B310 (bandit) — `app/medicare/record/lab.py:39`

CWE-918 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.70 · nguồn: bandit

**Phân tích:** Scheme đã giới hạn http/https nên file:// không khả thi (CWE-22 không áp dụng), nhưng urlopen vẫn nhận URL người dùng không có allowlist host; cùng gốc rễ với F1 (SSRF, R-14).

**Đề xuất sửa:** Sửa cùng F1: allowlist host LIS, chặn IP nội bộ và redirect trong lab.download.

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Tìm trong code không có X-Frame-Options hay CSP frame-ancestors; chỉ có nosniff ở endpoint tải lab. Ứng dụng không đặt header bảo mật toàn cục. | Thêm middleware toàn cục (trong app factory) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none', X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response. |
| xác nhận | MEDIUM | 10038 (zap) | `GET /login`, `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | nosniff chỉ đặt thủ công ở download_lab_result; các trang khác thiếu header. | Đặt X-Content-Type-Options: nosniff trong middleware toàn cục. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Thiếu nosniff toàn cục. | Đặt nosniff trong middleware toàn cục. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 58.5 s · 29 lần gọi LLM · 16 lần gọi công cụ · 124238 token vào / 9762 token ra · ≈ $0.2183 · chạm giới hạn: không</sub>
