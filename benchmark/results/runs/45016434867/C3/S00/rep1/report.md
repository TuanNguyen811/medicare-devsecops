<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 9 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 0 phát hiện mới do Agent tự tìm · commit `4705039`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.55 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.55 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.55 |

### Chi tiết

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP (DAST) quan sát phản hồi GET / thiếu X-Frame-Options hoặc CSP frame-ancestors. Phiên này không có công cụ đọc mã và diff trống, nên không có bằng chứng để bác bỏ. Có thể dẫn tới clickjacking trên giao diện HMS.

**Kịch bản khai thác:** Kẻ tấn công nhúng trang MediCare vào iframe trên site độc hại và lừa người dùng đã đăng nhập (ví dụ lễ tân) bấm vào nút ẩn.

**Đề xuất sửa:** Thêm một middleware chung trong app factory (FastAPI) để đặt X-Frame-Options: DENY và CSP có frame-ancestors 'none' cho mọi phản hồi, gồm cả trang HTML.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang GET /login thiếu header chống clickjacking, cùng nguyên nhân với F1. Không có bằng chứng mã để bác bỏ. Trang đăng nhập là mục tiêu clickjacking đáng chú ý.

**Kịch bản khai thác:** Trang login bị nhúng trong iframe để lừa người dùng nhập thông tin hoặc bấm thao tác ngoài ý muốn.

**Đề xuất sửa:** Dùng cùng middleware security headers toàn cục: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** GET / thiếu X-Content-Type-Options: nosniff. Đây là lỗi hardening toàn cục, rủi ro thấp.

**Kịch bản khai thác:** MIME sniffing trên trình duyệt.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware security headers toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** GET /health thiếu X-Content-Type-Options. Tác động rất thấp vì endpoint chỉ trả trạng thái, nhưng middleware toàn cục sẽ sửa luôn.

**Kịch bản khai thác:** Tác động thực tế không đáng kể.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff trong middleware security headers toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP báo GET /login thiếu X-Content-Type-Options: nosniff. Đây là lỗi cấu hình hardening, mức thực tế thấp. Không có bằng chứng mã để bác bỏ.

**Kịch bản khai thác:** Trình duyệt có thể đoán MIME của tài nguyên, mở đường cho tấn công MIME sniffing khi có nội dung do người dùng kiểm soát.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security headers toàn cục, đặt X-Content-Type-Options: nosniff cho mọi phản hồi.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Phản hồi POST /appointments không có Content-Security-Policy. Đây là thiếu hardening toàn ứng dụng, không phải lỗi riêng của route. Không có mã để bác bỏ.

**Kịch bản khai thác:** Nếu có XSS ở nơi khác, việc thiếu CSP khiến script bị thực thi mà không bị giới hạn.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') qua middleware toàn cục, áp dụng cả phản hồi POST và redirect.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Phản hồi POST /appointments/{appointment_id}/confirm thiếu CSP, cùng nguyên nhân toàn cục như F6.

**Kịch bản khai thác:** Như F6: thiếu lớp giảm thiểu XSS.

**Đề xuất sửa:** Sửa một lần bằng middleware CSP toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Phản hồi POST /patients thiếu CSP, cùng nguyên nhân toàn cục như F6. Trang chứa dữ liệu bệnh nhân nên cần có CSP.

**Kịch bản khai thác:** Như F6.

**Đề xuất sửa:** Sửa một lần bằng middleware CSP toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.55 · nguồn: zap

**Phân tích:** Phản hồi POST /patients/{patient_id}/edit thiếu CSP, cùng nguyên nhân toàn cục như F6.

**Kịch bản khai thác:** Như F6.

**Đề xuất sửa:** Sửa một lần bằng middleware CSP toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 43.9 s · 3 lần gọi LLM · 10 lần gọi công cụ · 24325 token vào / 7857 token ra · ≈ $0.1322 · chạm giới hạn: không</sub>
