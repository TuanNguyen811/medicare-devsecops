<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 12 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `bfd2192`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | CRITICAL | trivy | CVE-2020-14343 (trivy) | `app/uv.lock:1` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | semgrep | package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) | `app/pyproject.toml:43` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |

### Chi tiết

#### 🔴 TP · CRITICAL · CVE-2020-14343 (trivy) — `app/uv.lock:1`

CWE-502 · OWASP A03 · vi phạm R-14 · độ tin cậy 0.95 · nguồn: trivy

**Phân tích:** PyYAML 5.3.1 dính CVE-2020-14343 (full_load thực thi mã tuỳ ý). Package được import và đạt tới: price_list.parse gọi yaml.full_load trên file do người dùng upload qua /admin/medicines/import. PR còn hạ phiên bản từ 6.0.3 xuống 5.3.1 có chủ đích.

**Kịch bản khai thác:** Admin (hoặc kẻ chiếm tài khoản admin/CSRF) upload file YAML chứa payload python/object/new, full_load của 5.3.1 thực thi mã trên server.

**Đề xuất sửa:** Trong app/pyproject.toml đổi lại thành pyyaml>=6.0.3 (bỏ pin ==5.3.1 và build-constraint setuptools<81), cập nhật lại uv.lock. Trong price_list.parse thay yaml.full_load bằng yaml.safe_load.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** search_code không thấy ứng dụng đặt header bảo mật nào (X-Frame-Options, CSP, X-Content-Type-Options), nên phát hiện ZAP là thật (cấu hình thiếu toàn cục, không do PR này).

**Đề xuất sửa:** Thêm middleware bảo mật trong app factory đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff và Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Ứng dụng không đặt header chống clickjacking ở đâu (search_code rỗng).

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong code ứng dụng.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong ứng dụng.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong ứng dụng.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong ứng dụng.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong ứng dụng.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy trong ứng dụng.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · LOW · package_managers.uv.uv-missing-dependency-cooldown.uv-missing-dependency-cooldown (semgrep) — `app/pyproject.toml:43`

CWE-829 · OWASP A03 · độ tin cậy 0.60 · nguồn: semgrep

**Phân tích:** Khối [tool.uv] mới thêm không đặt exclude-newer (cooldown) nên có thể kéo gói mới phát hành chưa kiểm chứng. Rủi ro thấp vì có uv.lock.

**Đề xuất sửa:** Trong [tool.uv] của app/pyproject.toml thêm exclude-newer = "7 days" (cooldown phụ thuộc).

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong ứng dụng.

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options trong ứng dụng; endpoint /health ít rủi ro.

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 34.4 s · 17 lần gọi LLM · 16 lần gọi công cụ · 80362 token vào / 5112 token ra · ≈ $0.1343 · chạm giới hạn: không</sub>
