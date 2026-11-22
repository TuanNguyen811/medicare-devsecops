<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `18982a4`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | agent | Mất ràng buộc DB chống đặt trùng lịch bác sĩ, kiểm tra overlap chỉ ở tầng ứng dụng (race condition) | `app/medicare/appointment/service.py:133` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/quick:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients:0` | 0.50 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.50 |

### Chi tiết

#### 🔴 TP · MEDIUM · Mất ràng buộc DB chống đặt trùng lịch bác sĩ, kiểm tra overlap chỉ ở tầng ứng dụng (race condition) — `app/medicare/appointment/service.py:133`

CWE-362 · OWASP A06 · vi phạm R-13 · độ tin cậy 0.85 · nguồn: agent

**Phân tích:** PR xóa unique index `uq_doctor_slot_active` và bỏ xử lý IntegrityError. `book()` giờ chỉ gọi `_active_around()` (SELECT) rồi `db.add` và `flush` mà không có khóa hay ràng buộc DB. Hai request đồng thời cùng thấy khung giờ trống và cùng insert, nên một bác sĩ có hai lịch hẹn còn hiệu lực trùng giờ, vi phạm R-13. Trước đây DB là nguồn sự thật. Tính năng đặt lịch nhanh cho phép bất kỳ bệnh nhân nào gọi endpoint này, nên dễ khai thác bằng request song song.

**Kịch bản khai thác:** Kẻ tấn công hoặc hai người dùng gửi đồng thời nhiều POST /appointments/quick cho cùng bác sĩ và giờ. Cả hai kiểm tra overlap đều trả rỗng, cả hai insert thành công, tạo lịch trùng giờ.

**Đề xuất sửa:** Trong service.book(), tuần tự hóa việc đặt lịch theo bác sĩ: lấy khóa hàng bằng `select(User).where(User.id == doctor_id).with_for_update()` trước khi gọi `_active_around`, hoặc dùng `pg_advisory_xact_lock(doctor_id)`. Hoặc thêm vào migration 0004 một exclusion constraint PostgreSQL (btree_gist) trên (doctor_id, tstzrange(scheduled_at, scheduled_at + duration_minutes)) với điều kiện status <> 'CANCELLED', và bắt IntegrityError để ném Conflict(DOUBLE_BOOKED) như trước. Cập nhật test để kiểm tra đồng thời.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** ZAP (DAST) thấy phản hồi thiếu X-Frame-Options / frame-ancestors. Trong code được cung cấp không có middleware đặt header bảo mật, nên đây là lỗi cấu hình thật.

**Đề xuất sửa:** Thêm middleware toàn cục (trong app factory/main) đặt `X-Frame-Options: DENY` và CSP `frame-ancestors 'none'` cho mọi phản hồi.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Trang /login thiếu chống clickjacking; trang đăng nhập là mục tiêu điển hình. Không thấy header bảo mật được đặt ở đâu trong code.

**Đề xuất sửa:** Dùng middleware header bảo mật toàn cục: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu header nosniff trên GET /; không thấy middleware đặt header.

**Đề xuất sửa:** Middleware toàn cục thêm `X-Content-Type-Options: nosniff`.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu nosniff trên /health; cùng nguyên nhân cấu hình chung, rủi ro thấp.

**Đề xuất sửa:** Middleware toàn cục thêm `X-Content-Type-Options: nosniff` cho mọi route kể cả /health.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Thiếu `X-Content-Type-Options: nosniff` và CSP trên /login; không có middleware đặt header trong code đã xem.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm `X-Content-Type-Options: nosniff` và Content-Security-Policy.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Thiếu CSP là vấn đề cấu hình chung của ứng dụng; phản hồi lỗi 400/409 render HTML. Mức ảnh hưởng thấp vì Jinja2 autoescape.

**Đề xuất sửa:** Thêm CSP toàn cục qua middleware (default-src 'self', không dùng inline script).

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/quick:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Route /appointments/quick mới trả HTML (quick.html) không có CSP. Cùng nguyên nhân cấu hình chung.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Cùng lỗi thiếu CSP toàn cục, ảnh hưởng mọi phản hồi.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Cùng lỗi thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.50 · nguồn: zap

**Phân tích:** Cùng lỗi thiếu CSP toàn cục.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `single-shot` · 36.6 s · 13 lần gọi LLM · 12 lần gọi công cụ · 75859 token vào / 5466 token ra · ≈ $0.2131 · chạm giới hạn: không</sub>
