<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 0 lỗi thật (TP) · 11 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `1e62304`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/insurance-check:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | bandit | B404 (bandit) | `app/medicare/patient/insurance_check.py:10` | 0.90 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.40 |
| 🟢 FP | LOW | bandit | B603 (bandit) | `app/medicare/patient/insurance_check.py:57` | 0.88 |

### Chi tiết

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Phát hiện DAST về header; PR không đụng tới middleware header nên không có bằng chứng trong code đã đọc để xác nhận hay bác bỏ. Cần kiểm tra middleware/reverse proxy.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Frame-Options/frame-ancestors trên /login; không có bằng chứng trong code đã đọc về việc header được đặt ở nơi khác. Cần kiểm tra middleware/proxy.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /login; không đủ bằng chứng trong phạm vi PR.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt; vấn đề cấu hình toàn cục, không do PR; cần kiểm tra middleware.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt; vấn đề cấu hình toàn cục, cần kiểm tra middleware.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt; vấn đề cấu hình toàn cục, cần kiểm tra middleware.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt; vấn đề cấu hình toàn cục, cần kiểm tra middleware.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/insurance-check:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** CSP không được đặt trên endpoint mới; là cấu hình toàn cục, cần kiểm tra middleware. Bản thân route đã có CSRF và editor_user.

#### 🟡 NEEDS_REVIEW · LOW · B404 (bandit) — `app/medicare/patient/insurance_check.py:10`

CWE-78 · độ tin cậy 0.90 · nguồn: bandit

**Phân tích:** [Bằng chứng cho FP phải trích đoạn mã (≥ 10 ký tự) tại vị trí phát hiện hoặc trong file liên quan] B404 chỉ cảnh báo việc import subprocess, không phải lỗ hổng. Việc dùng ở check_card an toàn: truyền list đối số, không shell, thẻ được kiểm tra định dạng.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /; cần kiểm tra middleware/proxy.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; tác động thấp, cần kiểm tra middleware.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B603 (bandit)** — `app/medicare/patient/insurance_check.py:57`: subprocess.run nhận list đối số (không shell=True), executable lấy từ cấu hình env chứ không từ người dùng. Mã thẻ được xác thực bằng is_valid_insurance_number, họ tên được chuẩn hóa/giới hạn, và mọi giá trị đi dạng --name=value nên không thể thành option riêng. Có timeout. Không có command/argument injection.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 29.6 s · 14 lần gọi LLM · 13 lần gọi công cụ · 54440 token vào / 4142 token ra · ≈ $0.1520 · chạm giới hạn: không</sub>
