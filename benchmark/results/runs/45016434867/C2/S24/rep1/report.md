<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `f923a00`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Bỏ qua khóa tài khoản và đếm lần sai khi có cookie remember-me bất kỳ (brute-force không giới hạn) | `app/medicare/common/auth.py:54` | 0.90 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Bỏ qua khóa tài khoản và đếm lần sai khi có cookie remember-me bất kỳ (brute-force không giới hạn) — `app/medicare/common/auth.py:54`

CWE-307 · OWASP A07 · vi phạm R-07 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** authenticate() với remembered_device=True bỏ qua kiểm tra locked_until và không tăng failed_login_count. Cờ này được tính bởi is_remembered_device(), chỉ kiểm tra cookie có token hợp lệ của BẤT KỲ user nào, không ràng buộc với username đang đăng nhập. Kẻ tấn công có tài khoản hợp lệ (ví dụ bệnh nhân) bật "ghi nhớ", rồi gửi cookie đó kèm username của bác sĩ/admin để đoán mật khẩu không giới hạn, vô hiệu hóa R-07 (khóa 15 phút sau 5 lần sai). Cookie bị đánh cắp cũng cho phép tương tự.

**Kịch bản khai thác:** Kẻ tấn công đăng ký/đăng nhập bằng tài khoản của mình với remember_me=on, nhận cookie medicare_remember, rồi POST /login hàng loạt với username nạn nhân và danh sách mật khẩu, kèm cookie đó. Tài khoản không bao giờ bị khóa nên đoán được mật khẩu.

**Đề xuất sửa:** Xóa tham số remembered_device khỏi authenticate() và router.login: luôn áp dụng khóa tài khoản và đếm failed_login_count cho mọi lần đăng nhập bằng mật khẩu (R-07). Remember-me chỉ dùng để khôi phục session trong get_current_user, không được nới lỏng kiểm tra mật khẩu. Ngoài ra nên xóa bản ghi RememberToken trong DB khi logout (hiện chỉ xóa cookie) và cân nhắc xoay vòng token mỗi lần dùng.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có middleware nào đặt X-Frame-Options / CSP frame-ancestors; main.py chỉ thêm Session, Metrics và CatchAll. Trang có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware trong app/medicare/main.py đặt X-Frame-Options: DENY và Content-Security-Policy (frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Như F1: trang /login (có form đăng nhập) thiếu header chống clickjacking vì không có middleware đặt header bảo mật.

**Đề xuất sửa:** Thêm middleware security headers trong main.py (X-Frame-Options: DENY, CSP frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm middleware đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm middleware CSP chung trong main.py.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong ứng dụng.

**Đề xuất sửa:** Thêm middleware CSP chung trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options: nosniff; không có middleware đặt header.

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff trong main.py.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** /health cũng thiếu X-Content-Type-Options; rủi ro thấp nhưng sửa chung bằng middleware.

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff trong main.py.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong mã.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response trong main.py.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 41.8 s · 17 lần gọi LLM · 16 lần gọi công cụ · 118454 token vào / 6340 token ra · ≈ $0.1558 · chạm giới hạn: không</sub>
