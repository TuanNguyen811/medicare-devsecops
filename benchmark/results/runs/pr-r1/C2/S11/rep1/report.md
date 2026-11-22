<!-- secagent-report -->
## 🛡️ AI Security Agent

**Code của PR này:** 🔴 2 lỗi cần sửa

📋 10 cảnh báo khi quét ứng dụng đang chạy, xem cuối báo cáo · commit `df5a186`

### 🔴 Lỗi cần sửa

| | Mức | Lỗ hổng | Vị trí | Nguồn | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | CVE-2020-14343 (trivy) | `app/uv.lock:1` | trivy | 0.95 |
| 🔴 TP | LOW | package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) | `app/pyproject.toml:43` | semgrep | 0.50 |

### Chi tiết

#### 🔴 TP · CRITICAL · CVE-2020-14343 (trivy) — `app/uv.lock:1`

CWE-502 · OWASP A03 · độ tin cậy 0.95 · nguồn: trivy

**Phân tích:** PR hạ cấp pyyaml xuống 5.3.1 (dính CVE-2020-14343) và price_list.parse gọi yaml.full_load trên nội dung file do người dùng tải lên. Với 5.3.1, full_load cho phép tạo đối tượng Python tùy ý và thực thi mã (RCE). Hàm dễ bị tấn công được gọi trực tiếp từ route /admin/medicines/import. Comment trong pyproject.toml ("Same PyYAML as the pharmacy stock system") không phải lý do bảo mật chính đáng.

**Kịch bản khai thác:** Kẻ tấn công kiểm soát tài khoản ADMIN (hoặc dùng CSRF/file bảng giá giả mạo từ nhà cung cấp) tải lên file YAML chứa tag python/object/new để chạy lệnh tùy ý trên server, đọc toàn bộ dữ liệu bệnh nhân.

**Đề xuất sửa:** Trong app/pyproject.toml đặt lại pyyaml>=6.0.3 (hoặc ít nhất >=5.4) và cập nhật uv.lock, bỏ build-constraint setuptools<81. Trong price_list.parse thay yaml.full_load bằng yaml.safe_load. Có thể kiểm tra thêm schema.

#### 🔴 TP · LOW · package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) — `app/pyproject.toml:43`

CWE-829 · OWASP A03 · độ tin cậy 0.50 · nguồn: semgrep

**Phân tích:** Phần [tool.uv] mới được thêm nhưng chưa đặt exclude-newer (cooldown), nên gói mới phát hành có thể bị kéo vào ngay. Đây là khuyến nghị hardening chuỗi cung ứng, rủi ro thấp.

**Đề xuất sửa:** Trong khối [tool.uv] của app/pyproject.toml thêm exclude-newer với khoảng cooldown (ví dụ 7 ngày).

<details><summary>📋 Cảnh báo khi quét ứng dụng đang chạy (ZAP): 10</summary>

Các cảnh báo này đến từ việc quét ứng dụng đang chạy. Chúng thường là cấu hình chung của ứng dụng (ví dụ header bảo mật), có thể đã có từ trước PR này, và không làm PR bị chặn ở mức MEDIUM/LOW.

| Kết luận | Mức | Cảnh báo | Route | Phân tích | Đề xuất sửa |
|---|---|---|---|---|---|
| xác nhận | MEDIUM | 10020 (zap) | `GET /`, `GET /login` | Tìm trong mã nguồn không thấy X-Frame-Options, Content-Security-Policy hay nosniff được đặt ở đâu, khớp với kết quả ZAP. | Thêm middleware đặt header bảo mật cho mọi response: X-Frame-Options DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options nosniff, Content-Security-Policy. |
| xác nhận | MEDIUM | 10038 (zap) | `POST /appointments`, `POST /appointments/{appointment_id}/cancel`, `POST /appointments/{appointment_id}/confirm`, `POST /patients`, `POST /patients/{patient_id}/edit` | Không có Content-Security-Policy nào được đặt trong mã nguồn. | Thêm Content-Security-Policy chặt chẽ qua middleware chung cho mọi response. |
| xác nhận | LOW | 10021 (zap) | `GET /`, `GET /health` | Không có header X-Content-Type-Options trong mã nguồn. | Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response. |
| xác nhận | LOW | 10038 (zap) | `GET /login` | Không có header X-Content-Type-Options trong mã nguồn. | Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response. |

</details>

---
<sub>model `claude-sonnet-5-5` · chiến lược `agent` · 36.9 s · 16 lần gọi LLM · 15 lần gọi công cụ · 82109 token vào / 5568 token ra · ≈ $0.1401 · chạm giới hạn: không</sub>
