<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 1 lỗi thật (TP) · 10 cần người xem (NEEDS_REVIEW) · 1 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `f95ff81`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | gitleaks | generic-api-key (gitleaks) | `app/medicare/appointment/sms.py:13` | 0.90 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:GET /login:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/remind:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.40 |
| 🟡 NEEDS_REVIEW | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.40 |
| 🟡 NEEDS_REVIEW | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.40 |
| 🟢 FP | LOW | bandit | B310 (bandit) | `app/medicare/appointment/sms.py:50` | 0.90 |

### Chi tiết

#### 🔴 TP · HIGH · generic-api-key (gitleaks) — `app/medicare/appointment/sms.py:13`

CWE-798 · OWASP A04 · vi phạm R-09 · độ tin cậy 0.90 · nguồn: gitleaks

**Phân tích:** Gitleaks và Bandit cùng báo dòng 13-14 của sms.py: ESMS_API_KEY và ESMS_SECRET_KEY được gán trực tiếp trong mã nguồn. Hai hằng số này được dùng ở send_sms (dòng 36-37) để xác thực với cổng eSMS.vn. Như vậy vi phạm R-09, vì secret chỉ được đọc từ biến môi trường. Ai đọc được repo cũng có thể gửi SMS brandname bằng danh nghĩa MEDICARE.

**Kịch bản khai thác:** Kẻ có quyền đọc repo hoặc lịch sử git lấy ApiKey/SecretKey, rồi gọi API eSMS.vn để gửi SMS giả mạo brandname MEDICARE (lừa đảo, phishing) và làm hết số dư tài khoản SMS.

Gộp các phát hiện: `bandit:B105:app/medicare/appointment/sms.py:14`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:13`, `gitleaks:generic-api-key:app/medicare/appointment/sms.py:14`

**Đề xuất sửa:** Xóa hai giá trị hard-code khỏi sms.py. Đọc ESMS_API_KEY và ESMS_SECRET_KEY từ biến môi trường (qua cơ chế cấu hình/settings của app, giống SECRET_KEY theo R-09) và báo lỗi khi thiếu. Thu hồi và cấp lại cặp khóa đã lộ trên eSMS.vn, đồng thời xóa chúng khỏi lịch sử git.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Đây là cảnh báo header phản hồi từ DAST, nhưng PR này không đụng đến middleware hay cấu hình header. Tôi chưa có bằng chứng về nơi đặt security headers (X-Frame-Options hoặc frame-ancestors) để kết luận.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Cùng lỗi thiếu header chống clickjacking với F3, ở trang /login. PR không chứa code cấu hình header nên chưa đủ bằng chứng. Cần kiểm tra middleware toàn cục.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:GET /login:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options ở /login. Đây là cấu hình toàn cục, không nằm trong code PR, nên tôi chưa đủ bằng chứng. Nên thêm header này vào middleware chung.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP ở POST /appointments. Vấn đề cấu hình toàn cục, nằm ngoài code PR và tôi không có bằng chứng về middleware.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP ở endpoint confirm. Đây là vấn đề header toàn cục, chưa có bằng chứng từ code PR.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/remind:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP ở endpoint remind mới. Endpoint chỉ trả RedirectResponse 303 nên tác động thấp. Header CSP phải xử lý ở middleware toàn cục, chưa đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP ở POST /patients. Cấu hình toàn cục, ngoài code PR, chưa đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu CSP ở POST /patients/{patient_id}/edit. Cấu hình toàn cục, ngoài code PR, chưa đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options ở GET /. Đây là header toàn cục, PR không chứa cấu hình liên quan nên chưa đủ bằng chứng.

#### 🟡 NEEDS_REVIEW · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · độ tin cậy 0.40 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options ở /health. Đây là header toàn cục, PR không chứa cấu hình liên quan nên chưa đủ bằng chứng.

<details><summary>🟢 Báo nhầm (FP): 1</summary>

- **B310 (bandit)** — `app/medicare/appointment/sms.py:50`: urlopen chỉ nhận Request dựng từ hằng số ESMS_URL với scheme https cố định. Không có phần nào của URL đến từ người dùng, nên không thể dùng file:/ hoặc scheme tùy ý và không có SSRF (R-14 không bị vi phạm). Dữ liệu người dùng (phone, text) chỉ nằm trong JSON body.

</details>

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 34.2 s · 14 lần gọi LLM · 13 lần gọi công cụ · 58922 token vào / 5137 token ra · ≈ $0.1732 · chạm giới hạn: không</sub>
