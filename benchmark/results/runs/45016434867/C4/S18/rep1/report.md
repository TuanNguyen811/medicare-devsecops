<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 11 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `18982a4`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | MEDIUM | agent | Đặt lịch trùng giờ do race condition sau khi bỏ unique index | `app/medicare/appointment/service.py:133` | 0.70 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.85 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/quick:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · MEDIUM · Đặt lịch trùng giờ do race condition sau khi bỏ unique index — `app/medicare/appointment/service.py:133`

CWE-362 · OWASP A06 · độ tin cậy 0.70 · nguồn: agent

**Phân tích:** PR bỏ unique index uq_doctor_slot_active (DB là nguồn sự thật) và chuyển sang kiểm tra trùng ở tầng ứng dụng: service.book gọi _active_around rồi mới insert. Đây là check-then-act không có khóa. Hai request đồng thời cho cùng bác sĩ/giờ đều thấy rỗng và cùng insert, gây double-booking. Index mới ix_appointments_doctor_id_scheduled_at không unique nên DB không còn chặn được.

**Kịch bản khai thác:** Kẻ tấn công (hoặc người dùng thường) gửi song song nhiều POST /appointments/quick cho cùng doctor_id và scheduled_at. Tất cả vượt qua kiểm tra trùng và cùng được insert, nên bác sĩ bị đặt trùng giờ.

**Đề xuất sửa:** Trong service.book, khóa dòng bác sĩ bằng SELECT ... FOR UPDATE (with_for_update trên db.get(User, doctor_id)) trước khi gọi _active_around, để các lần đặt lịch cùng bác sĩ chạy tuần tự. Hoặc thêm exclusion constraint PostgreSQL (tstzrange với btree_gist) trong migration 0004 để DB chặn chồng lịch, rồi bắt IntegrityError và chuyển thành Conflict(DOUBLE_BOOKED).

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** create_app trong app/medicare/main.py chỉ thêm CatchAllErrorsMiddleware, SessionMiddleware và MetricsMiddleware. Không có chỗ nào trong repo đặt X-Frame-Options hay CSP frame-ancestors, nên trang có thể bị nhúng vào iframe (clickjacking).

**Đề xuất sửa:** Thêm một middleware security-headers trong create_app (app/medicare/main.py), đặt X-Frame-Options: DENY (hoặc CSP frame-ancestors 'none') cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.85 · nguồn: zap

**Phân tích:** Trang /login không có X-Frame-Options hay frame-ancestors; main.py không có middleware đặt header bảo mật.

**Đề xuất sửa:** Dùng chung middleware security-headers trong create_app, đặt X-Frame-Options: DENY.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Không có Content-Security-Policy ở bất kỳ đâu trong repo.

**Đề xuất sửa:** Thêm header Content-Security-Policy (default-src 'self', frame-ancestors 'none') trong middleware toàn cục ở create_app.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/quick:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân với F6. Route /appointments/quick mới trả HTML mà không có CSP.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân với F6.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân với F6.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Thiếu CSP, cùng nguyên nhân với F6.

**Đề xuất sửa:** Thêm CSP bằng middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu header nosniff, cùng nguyên nhân với F5.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff bằng middleware toàn cục.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Thiếu header nosniff trên /health, cùng nguyên nhân với F5.

**Đề xuất sửa:** Đặt X-Content-Type-Options: nosniff bằng middleware toàn cục.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có X-Content-Type-Options: nosniff ở bất kỳ đâu trong repo.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Trong middleware security-headers ở create_app, đặt X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 59.6 s · 27 lần gọi LLM · 16 lần gọi công cụ · 150189 token vào / 9871 token ra · ≈ $0.2154 · chạm giới hạn: không</sub>
