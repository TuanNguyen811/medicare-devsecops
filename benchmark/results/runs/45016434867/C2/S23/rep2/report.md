<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `8855b63`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Bác sĩ bất kỳ có thể tự nhận phụ trách bệnh nhân bất kỳ (IDOR / leo thang quyền) | `app/medicare/patient/service.py:129` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/claim:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Bác sĩ bất kỳ có thể tự nhận phụ trách bệnh nhân bất kỳ (IDOR / leo thang quyền) — `app/medicare/patient/service.py:129`

CWE-639 · OWASP A01 · vi phạm R-02 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** service.claim_patient chỉ kiểm tra vai trò DOCTOR (ở router) rồi gán attending_doctor_id = doctor.id cho bất kỳ patient_id nào, không qua policy.can_*. Không kiểm tra cùng khoa, nên bác sĩ khoa khác chiếm quyền phụ trách, từ đó được xem/sửa bệnh án và kê đơn (R-02, R-03). Khi bệnh nhân chưa có khoa, bác sĩ còn gán luôn khoa của mình. Không có audit log và không có bước đối chiếu bác sĩ phụ trách hiện tại. Bệnh nhân không tồn tại và không có quyền cũng không trả 404 giống nhau (R-15).

**Kịch bản khai thác:** Bác sĩ khoa A đăng nhập, gửi POST /patients/{id}/claim với id bất kỳ (enumerate), trở thành bác sĩ phụ trách, rồi đọc bệnh án và kê đơn cho bệnh nhân không thuộc khoa mình.

**Đề xuất sửa:** Thêm hàm policy.can_claim_patient(user, patient) trong app/medicare/policy.py (ghi mã R-02), chỉ cho phép bác sĩ cùng khoa (department_id cả hai khác rỗng và bằng nhau); nếu không đạt thì raise NotFound (404, R-15). Gọi hàm này trong service.claim_patient trước khi gán attending_doctor_id, và dùng chính hàm đó cho cờ can_claim trong _detail_ctx. Không tự gán department_id từ bác sĩ cho bệnh nhân chưa có khoa. Ghi audit log cho thao tác nhận phụ trách; cân nhắc yêu cầu admin duyệt hoặc bác sĩ hiện tại bàn giao.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy ứng dụng đặt X-Frame-Options hay CSP frame-ancestors, nên phản hồi thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware đặt header bảo mật cho mọi phản hồi: X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/claim:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo, phản hồi của route claim cũng thiếu.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Middleware chung thêm Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options, không có middleware đặt header.

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân thiếu middleware header.

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff cho mọi route.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware chung thêm X-Content-Type-Options: nosniff cho mọi phản hồi.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 37.0 s · 16 lần gọi LLM · 15 lần gọi công cụ · 76375 token vào / 5204 token ra · ≈ $0.0850 · chạm giới hạn: không</sub>
