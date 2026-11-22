<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `18982a4`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | agent | Đặt lịch trùng giờ do race condition (check-then-insert, bỏ unique index) | `app/medicare/appointment/service.py:133` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/quick:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.70 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · Đặt lịch trùng giờ do race condition (check-then-insert, bỏ unique index) — `app/medicare/appointment/service.py:133`

CWE-362 · OWASP A06 · vi phạm R-13 · độ tin cậy 0.80 · nguồn: agent

**Phân tích:** PR xóa unique index uq_doctor_slot_active và thay bằng kiểm tra trùng ở tầng ứng dụng (_active_around rồi insert) mà không có khóa. Hai request đồng thời cùng thấy khung giờ trống và cùng insert, vi phạm R-13 (một bác sĩ không có hai lịch còn hiệu lực trùng giờ). Trước đây DB là nguồn chân lý.

**Kịch bản khai thác:** Kẻ tấn công hoặc hai lễ tân gửi đồng thời nhiều POST /appointments/quick cho cùng bác sĩ và giờ; cả hai qua bước kiểm tra và đều được ghi, tạo lịch trùng.

**Đề xuất sửa:** Trong service.book, serialize theo bác sĩ: khóa hàng bác sĩ bằng SELECT ... FOR UPDATE (with_for_update trên db.get/select User) hoặc pg_advisory_xact_lock(doctor_id) trước khi gọi _active_around. Hoặc thêm exclusion constraint PostgreSQL (btree_gist) trên doctor_id và tstzrange(scheduled_at, scheduled_at + duration) WHERE status <> 'CANCELLED' trong migration 0004, rồi bắt IntegrityError và raise Conflict.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy nơi nào đặt X-Frame-Options hay frame-ancestors; ứng dụng không gửi header chống clickjacking.

**Đề xuất sửa:** Thêm middleware security headers toàn ứng dụng (app factory/main) đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware security headers chung: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/quick:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo, gồm cả route /appointments/quick mới.

**Đề xuất sửa:** Middleware toàn ứng dụng thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có CSP nào trong repo.

**Đề xuất sửa:** Middleware toàn ứng dụng thêm Content-Security-Policy chặt.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options trên toàn ứng dụng.

**Đề xuất sửa:** Middleware toàn ứng dụng thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Thiếu X-Content-Type-Options; /health cũng không có header, cùng nguyên nhân toàn cục.

**Đề xuất sửa:** Middleware toàn ứng dụng thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn ứng dụng thêm X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 34.4 s · 16 lần gọi LLM · 15 lần gọi công cụ · 115290 token vào / 5027 token ra · ≈ $0.0893 · chạm giới hạn: không</sub>
