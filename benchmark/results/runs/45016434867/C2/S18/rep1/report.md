<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `18982a4`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | agent | Race condition đặt trùng lịch bác sĩ: bỏ unique index, kiểm tra trùng không có khóa | `app/medicare/appointment/service.py:133` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/quick:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.65 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.65 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.65 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · MEDIUM · Race condition đặt trùng lịch bác sĩ: bỏ unique index, kiểm tra trùng không có khóa — `app/medicare/appointment/service.py:133`

CWE-362 · OWASP A06 · vi phạm R-13 · độ tin cậy 0.80 · nguồn: agent

**Phân tích:** PR xóa index unique uq_doctor_slot_active (DB là nguồn sự thật) và thay bằng kiểm tra check-then-insert trong book(): _active_around rồi db.add/flush, không có khóa hàng hay ràng buộc. Hai request đồng thời cùng thấy khung giờ trống và đều insert thành công, vi phạm R-13 (một bác sĩ không có hai lịch hẹn còn hiệu lực trùng giờ).

**Kịch bản khai thác:** Hai bệnh nhân (hoặc một kẻ gửi song song nhiều request) POST /appointments/quick cùng doctor_id và giờ; cả hai qua kiểm tra trước khi bên kia commit, tạo hai lịch trùng giờ.

**Đề xuất sửa:** Trong service.book, khóa hàng bác sĩ (select(User).where(id==doctor_id).with_for_update()) hoặc dùng pg_advisory_xact_lock(doctor_id) trước khi gọi _active_around để tuần tự hóa việc đặt lịch cùng bác sĩ. Hoặc thêm ràng buộc ở DB: EXCLUDE USING gist (doctor_id WITH =, tstzrange(scheduled_at, scheduled_at + duration_minutes * interval '1 minute') WITH &&) WHERE status <> 'CANCELLED' trong migration 0004, và bắt IntegrityError để ném Conflict như trước.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay CSP frame-ancestors nào được đặt, nên ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware toàn cục (app factory/main) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware toàn cục đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào được đặt trong repo.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/quick:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo; áp dụng cả response của /appointments/quick.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Không có CSP trong repo.

**Đề xuất sửa:** Middleware toàn cục đặt Content-Security-Policy chặt.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.65 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên /health; cùng nguyên nhân thiếu middleware header toàn cục.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options: nosniff ở đâu cả.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 36.1 s · 16 lần gọi LLM · 15 lần gọi công cụ · 115689 token vào / 5173 token ra · ≈ $0.1528 · chạm giới hạn: không</sub>
