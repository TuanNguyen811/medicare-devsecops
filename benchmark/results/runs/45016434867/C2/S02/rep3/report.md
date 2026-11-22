<!-- secagent-report -->
## 🛡️ AI Security Agent

**Kết quả:** 13 lỗi thật (TP) · 0 cần người xem (NEEDS_REVIEW) · 0 báo nhầm (FP) · trong đó 3 phát hiện mới do Agent tự tìm · commit `6d5288d`

| | Mức | Nguồn | Phát hiện | Vị trí | Độ tin cậy |
|---|---|---|---|---|---|
| 🔴 TP | HIGH | agent | Path traversal qua tham số letterhead | `app/medicare/record/export.py:27` | 0.90 |
| 🔴 TP | HIGH | agent | IDOR: export_record không kiểm tra policy.can_view_record | `app/medicare/record/export.py:40` | 0.95 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10020 (zap) | `dast:GET /login:0` | 0.80 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/cancel:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /appointments/{appointment_id}/confirm:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients:0` | 0.75 |
| 🔴 TP | MEDIUM | zap | 10038 (zap) | `dast:POST /patients/{patient_id}/edit:0` | 0.75 |
| 🔴 TP | LOW | agent | Header Content-Disposition/export: audit trước khi kiểm tra quyền, nurse khác khoa xuất được | `app/medicare/record/router.py:122` | 0.40 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /:0` | 0.80 |
| 🔴 TP | LOW | zap | 10021 (zap) | `dast:GET /health:0` | 0.80 |
| 🔴 TP | LOW | zap | 10038 (zap) | `dast:GET /login:0` | 0.80 |

### Chi tiết

#### 🔴 TP · HIGH · Path traversal qua tham số letterhead — `app/medicare/record/export.py:27`

CWE-22 · OWASP A01 · vi phạm R-14 · độ tin cậy 0.90 · nguồn: agent

**Phân tích:** read_letterhead ghép trực tiếp tên do người dùng gửi (query letterhead) vào LETTERHEAD_DIR mà không đối chiếu allowlist. Giá trị như ../../../../etc/passwd hoặc đường dẫn tuyệt đối đọc được file bất kỳ (UTF-8) và nội dung được chèn vào phiếu xuất. Vi phạm R-14.

**Kịch bản khai thác:** GET /records/1/export?format=txt&letterhead=../../../../etc/passwd trả nội dung file hệ thống trong phần đầu phiếu; có thể đọc cả file cấu hình chứa secret.

**Đề xuất sửa:** Trong export.read_letterhead, chỉ chấp nhận name nằm trong tập export.letterheads() (allowlist); không hợp lệ thì dùng DEFAULT_LETTERHEAD hoặc trả 400. Không ghép đường dẫn từ input người dùng.

#### 🔴 TP · HIGH · IDOR: export_record không kiểm tra policy.can_view_record — `app/medicare/record/export.py:40`

CWE-639 · OWASP A01 · vi phạm R-01 · độ tin cậy 0.95 · nguồn: agent

**Phân tích:** get_record_for_export chỉ gọi db.get(MedicalRecord, record_id) rồi ghi audit, không gọi policy.can_view_record(user, patient). Mọi DOCTOR/NURSE/PATIENT đăng nhập đều xuất được bệnh án của bất kỳ bệnh nhân nào, vi phạm R-01, R-02, R-12. Ngoài ra bệnh án không tồn tại và không có quyền phải cùng trả 404 (R-15).

**Kịch bản khai thác:** Bệnh nhân A đăng nhập, gọi GET /records/<id người khác>/export?format=txt và tải chẩn đoán, ghi chú của bệnh nhân B bằng cách duyệt id tuần tự.

**Đề xuất sửa:** Trong export.get_record_for_export, sau khi lấy record, gọi policy.can_view_record(user, record.patient); nếu sai hoặc record không tồn tại thì raise NotFound (404 giống nhau, R-15). Chỉ ghi audit EXPORT_RECORD sau khi được phép (hoặc ghi cả lần bị từ chối). Dùng cùng cơ chế như record_detail.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Tìm trong repo không có X-Frame-Options hay frame-ancestors, nên ứng dụng thiếu header chống clickjacking.

**Đề xuất sửa:** Thêm middleware toàn cục trong app chính, đặt X-Frame-Options: DENY và CSP frame-ancestors 'none' cho mọi response.

#### 🔴 TP · MEDIUM · 10020 (zap) — `dast:GET /login:0`

CWE-1021 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Không có header chống clickjacking nào trong repo, kể cả trang /login.

**Đề xuất sửa:** Dùng middleware security headers chung: X-Frame-Options DENY và CSP frame-ancestors 'none'.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt (default-src 'self', frame-ancestors 'none').

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/cancel:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /appointments/{appointment_id}/confirm:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt.

#### 🔴 TP · MEDIUM · 10038 (zap) — `dast:POST /patients/{patient_id}/edit:0`

CWE-693 · OWASP A02 · độ tin cậy 0.75 · nguồn: zap

**Phân tích:** Repo không đặt Content-Security-Policy ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm Content-Security-Policy chặt.

#### 🔴 TP · LOW · Header Content-Disposition/export: audit trước khi kiểm tra quyền, nurse khác khoa xuất được — `app/medicare/record/router.py:122`

CWE-862 · OWASP A01 · độ tin cậy 0.40 · nguồn: agent

**Phân tích:** Ghi chú phụ: route dùng clinical_user chỉ theo vai trò, không có kiểm tra theo đối tượng; đã nêu ở finding IDOR.

**Đề xuất sửa:** Xem fix IDOR: dùng policy.can_view_record.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10021 (zap) — `dast:GET /health:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

#### 🔴 TP · LOW · 10038 (zap) — `dast:GET /login:0`

CWE-693 · OWASP A02 · độ tin cậy 0.80 · nguồn: zap

**Phân tích:** Repo không đặt X-Content-Type-Options ở đâu.

Gộp các phát hiện: `zap:10021:dast:GET /login:0`, `zap:10038:dast:GET /login:0`

**Đề xuất sửa:** Middleware toàn cục thêm X-Content-Type-Options: nosniff.

---
<sub>LLM `claude-mcp` · model `claude-sonnet-5-5` · chiến lược `agent` · 41.1 s · 17 lần gọi LLM · 16 lần gọi công cụ · 96988 token vào / 6360 token ra · ≈ $0.1008 · chạm giới hạn: không</sub>
