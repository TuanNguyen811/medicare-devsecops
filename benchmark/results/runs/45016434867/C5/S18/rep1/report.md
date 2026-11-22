<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `18982a4`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | agent | Race condition: đặt lịch trùng giờ do bỏ unique index và check-then-insert không khóa | `app/medicare/appointment/service.py:133` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/quick:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.60 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.60 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.70 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.60 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.70 |

### Chi tiết

#### 🔴 TP · MEDIUM · Race condition: đặt lịch trùng giờ do bỏ unique index và check-then-insert không khóa — `app/medicare/appointment/service.py:133`

CWE-362 · OWASP A06 · vi phạm R-13 · độ tin cậy 0.80 · nguồn: agent

**Phân tích:** PR xóa index unique uq_doctor_slot_active (DB từng là nguồn sự thật) và thay bằng kiểm tra _active_around rồi insert ở tầng ứng dụng, không có khóa hay ràng buộc DB. Hai request đồng thời cùng thấy slot trống và cùng insert, vi phạm R-13 (bác sĩ không có hai lịch còn hiệu lực trùng giờ).

**Kịch bản khai thác:** Hai bệnh nhân (hoặc một client gửi song song nhiều POST /appointments/quick) đặt cùng bác sĩ cùng giờ; cả hai vượt qua kiểm tra overlap trước khi bên kia commit, tạo hai lịch trùng.

**Đề xuất sửa:** Trong service.book, serialize theo bác sĩ: khóa hàng bác sĩ bằng db.get(User, doctor_id, with_for_update=True) hoặc pg_advisory_xact_lock(doctor_id) trước khi gọi _active_around. Hoặc thêm migration dùng PostgreSQL EXCLUDE constraint (btree_gist) trên doctor_id và tstzrange(scheduled_at, scheduled_at + duration) WHERE status <> 'CANCELLED', và bắt IntegrityError để ném Conflict(DOUBLE_BOOKED). Thêm test đồng thời.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không tìm thấy X-Frame-Options hay frame-ancestors ở bất kỳ đâu trong repo, nên ứng dụng có thể bị nhúng iframe (clickjacking).

**Đề xuất sửa:** Thêm middleware trong app factory (medicare main) đặt X-Frame-Options: DENY hoặc CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Trang /login không có header chống clickjacking; repo không đặt header bảo mật nào.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY / frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/quick:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo, kể cả response của /appointments/quick.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy cho mọi response.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy nào trong repo.

**Đề xuất sửa:** Thêm middleware toàn cục đặt Content-Security-Policy.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở đâu trong repo.

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.60 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở đâu trong repo (gồm /health).

**Đề xuất sửa:** Thêm middleware toàn cục đặt X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.70 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở đâu trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm middleware đặt X-Content-Type-Options: nosniff cho mọi response.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 35.3 s · 16 lần gọi LLM · 15 lần gọi công cụ · 111892 token vào / 5303 token ra · ≈ $0.1507 · chạm giới hạn: không</sub>
