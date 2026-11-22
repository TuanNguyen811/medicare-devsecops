<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 10 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 1 phát hiện mới do Agent tự tìm · commit `4773c9d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | quick_prescribe dùng can_view_record thay vì can_prescribe: y tá và bác sĩ cùng khoa kê đơn được | `app/medicare/prescription/service.py:71` | 0.92 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · quick_prescribe dùng can_view_record thay vì can_prescribe: y tá và bác sĩ cùng khoa kê đơn được — `app/medicare/prescription/service.py:71`

CWE-862 · OWASP A01 · vi phạm R-03 · độ tin cậy 0.92 · nguồn: agent

**Phân tích:** Route mới /records/{id}/prescriptions/quick cho phép DOCTOR và NURSE (ward_staff). Service chỉ kiểm tra policy.can_view_record, không kiểm tra policy.can_prescribe (hay get_record_for_prescribing như create_prescription). Theo R-03 chỉ bác sĩ phụ trách được kê đơn; y tá chỉ xem. Hậu quả: y tá và bác sĩ cùng khoa nhưng không phụ trách đều tạo được đơn thuốc cho bệnh nhân. Template record/detail.html cũng hiển thị form cho mọi DOCTOR/NURSE (can_quick_prescribe dựa trên role), và test hiện tại không bao phủ y tá.

**Kịch bản khai thác:** Y tá cùng khoa đăng nhập, mở phiếu khám, bấm "Kê đơn" với đơn mẫu bất kỳ (ví dụ da-day) và tạo đơn thuốc không có thẩm quyền; bác sĩ cùng khoa không phụ trách cũng làm được.

**Đề xuất sửa:** Trong service.quick_prescribe, thay đoạn db.get + can_view_record bằng get_record_for_prescribing(db, user, record_id) (như create_prescription), hoặc gọi policy.can_prescribe(user, patient) và trả NotFound khi bị từ chối. Ở router.py đổi dependency ward_staff thành doctor_user (chỉ Role.DOCTOR). Ở record/router.py đặt can_quick_prescribe = can_prescribe. Thêm test cho y tá và bác sĩ không phụ trách.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm toàn repo không thấy X-Frame-Options hay frame-ancestors, nên ứng dụng thật sự thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware trong app factory đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo; trang /login có thể bị nhúng vào iframe.

**Đề xuất sửa:** Dùng middleware chung đặt X-Frame-Options: DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none') trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt trong middleware chung.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Thêm Content-Security-Policy chặt trong middleware chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Thêm X-Content-Type-Options: nosniff trong middleware header bảo mật chung.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 34.7 s · 15 lần gọi LLM · 14 lần gọi công cụ · 80359 token vào / 5058 token ra · ≈ $0.1182 · chạm giới hạn: không</sub>
