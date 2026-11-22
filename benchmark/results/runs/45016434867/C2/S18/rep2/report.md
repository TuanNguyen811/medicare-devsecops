<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `18982a4`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | agent | Race condition đặt trùng lịch bác sĩ sau khi bỏ unique index (R-13) | `app/medicare/appointment/service.py:133` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/quick:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · Race condition đặt trùng lịch bác sĩ sau khi bỏ unique index (R-13) — `app/medicare/appointment/service.py:133`

CWE-362 · OWASP A06 · vi phạm R-13 · độ tin cậy 0.80 · nguồn: agent

**Phân tích:** PR xóa unique index uq_doctor_slot_active và chỉ kiểm tra chồng lấn bằng SELECT (_active_around) rồi INSERT ở tầng ứng dụng, không có khóa hay ràng buộc DB. Hai request đồng thời (READ COMMITTED) đều thấy slot trống và cùng chèn, tạo hai lịch hẹn còn hiệu lực trùng giờ cho một bác sĩ, vi phạm R-13. Trước đây DB là nguồn sự thật.

**Kịch bản khai thác:** Hai request POST /appointments/quick gửi cùng lúc cho cùng bác sĩ và giờ: cả hai qua kiểm tra _active_around rồi cùng commit, gây trùng lịch.

**Đề xuất sửa:** Trong service.book, tuần tự hóa việc đặt lịch theo bác sĩ: khóa hàng bác sĩ bằng SELECT ... FOR UPDATE (with_for_update trên db.get/select User) trước khi gọi _active_around, hoặc dùng pg_advisory_xact_lock(doctor_id). Hoặc thêm ràng buộc DB EXCLUDE USING gist (doctor_id, tstzrange(scheduled_at, scheduled_at + duration)) WHERE status <> 'CANCELLED' trong migration 0004 và bắt IntegrityError thành Conflict.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không thấy X-Frame-Options hay frame-ancestors nào, nên ứng dụng không chống clickjacking.

**Đề xuất sửa:** Thêm middleware đặt header bảo mật cho mọi response trong app factory: X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Frame-Options hay frame-ancestors trong repo; trang /login có thể bị nhúng iframe.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP (default-src 'self', frame-ancestors 'none') trong middleware header bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/quick:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware header bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware header bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware header bảo mật chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm CSP trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header nosniff trong repo.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware header bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header nosniff trong repo, kể cả /health.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware header bảo mật chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header X-Content-Type-Options: nosniff nào trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff vào middleware header bảo mật chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 35.5 s · 16 lần gọi LLM · 15 lần gọi công cụ · 113976 token vào / 5172 token ra · ≈ $0.0889 · chạm giới hạn: không</sub>
