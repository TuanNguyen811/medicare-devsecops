# Yêu cầu bảo mật nghiệp vụ: MediCare HMS

Tài liệu này mô tả **quy tắc bảo mật nghiệp vụ** mà MediCare HMS phải tuân thủ. Có ba nhóm sử dụng:

- **Lập trình viên:** mọi tính năng mới phải giữ đúng các quy tắc R-xx. Phân quyền theo đối tượng chỉ được thực hiện qua các hàm `can_*` trong `app/medicare/policy.py`. Docstring của mỗi hàm ghi mã quy tắc mà nó thực thi.
- **AI Security Agent:** đọc tài liệu này (công cụ `read_security_requirements`) để biết thế nào là *sai* đối với nghiệp vụ, từ đó phát hiện lỗi logic và phân quyền mà công cụ quét tĩnh không thấy được.
- **Bộ benchmark:** mỗi lỗ hổng logic trong `benchmark/ground_truth.yaml` được gắn với quy tắc bị vi phạm (`violated_rule: R-xx`).

## Vai trò

| Vai trò | Mô tả |
|---|---|
| `ADMIN` | Quản trị tài khoản, danh mục thuốc, xem audit log |
| `RECEPTIONIST` | Lễ tân: tiếp nhận bệnh nhân, quản lý lịch hẹn, lập và thu hóa đơn |
| `DOCTOR` | Bác sĩ: thuộc một khoa, phụ trách (`attending_doctor_id`) một số bệnh nhân |
| `NURSE` | Y tá: thuộc một khoa, chỉ xem |
| `PATIENT` | Bệnh nhân: tài khoản gắn với đúng một hồ sơ bệnh nhân (`users.patient_id`) |

Các khái niệm dùng trong ma trận:

- **"Cùng khoa":** `user.department_id` và `patient.department_id` đều khác rỗng và bằng nhau.
- **"Phụ trách":** `patient.attending_doctor_id == user.id`.
- **"Của mình":** `user.patient_id == patient.id`.

## Ma trận phân quyền

| Tài nguyên / hành động | ADMIN | RECEPTIONIST | DOCTOR | NURSE | PATIENT |
|---|---|---|---|---|---|
| Xem hồ sơ bệnh nhân | ✅ | ✅ | cùng khoa hoặc phụ trách | cùng khoa | của mình |
| Tạo / sửa hồ sơ bệnh nhân | ✅ | ✅ | ❌ | ❌ | ❌ |
| Xem CCCD, mã BHYT đầy đủ | ✅ | ✅ | ❌ (bị che) | ❌ (bị che) | của mình |
| Xem bệnh án | ❌ | ❌ | cùng khoa hoặc phụ trách | cùng khoa | của mình |
| Tạo / sửa bệnh án | ❌ | ❌ | phụ trách | ❌ | ❌ |
| Kê đơn thuốc | ❌ | ❌ | phụ trách | ❌ | ❌ |
| Xem đơn thuốc | ❌ | ❌ | cùng khoa hoặc phụ trách | cùng khoa | của mình |
| Xem lịch hẹn | ✅ | ✅ | lịch mình khám | bệnh nhân cùng khoa | của mình |
| Đặt lịch hẹn | ❌ | cho bất kỳ ai | ❌ | ❌ | cho chính mình |
| Xác nhận lịch hẹn | ❌ | ✅ | ❌ | ❌ | ❌ |
| Hủy lịch hẹn | ✅ (khi còn hiệu lực) | ✅ (khi còn hiệu lực) | ❌ | ❌ | của mình, khi `REQUESTED` |
| Lập / thu hóa đơn | ❌ | ✅ | ❌ | ❌ | ❌ |
| Xem hóa đơn | ✅ | ✅ | ❌ | ❌ | của mình |
| Quản lý tài khoản, danh mục thuốc | ✅ | ❌ | ❌ | ❌ | ❌ |
| Xem audit log | ✅ | ❌ | ❌ | ❌ | ❌ |

## Quy tắc

### R-01: Bệnh nhân chỉ truy cập dữ liệu của chính mình

Bệnh nhân chỉ xem được hồ sơ, bệnh án, đơn thuốc, hóa đơn, lịch hẹn của chính mình.

### R-02: Phạm vi xem và sửa bệnh án của bác sĩ

Bác sĩ xem được bệnh án của bệnh nhân thuộc khoa mình hoặc do mình phụ trách. Chỉ bác sĩ phụ trách (`attending_doctor_id`) được tạo hoặc sửa bệnh án.

### R-03: Kê đơn thuốc

Chỉ bác sĩ phụ trách được kê đơn. Y tá chỉ xem đơn của bệnh nhân thuộc khoa mình.

### R-04: Viện phí và BHYT tính ở server

Tỷ lệ BHYT chi trả và số tiền được tính ở server từ mã thẻ BHYT. Client không gửi lên tỷ lệ hay số tiền.

Mức hưởng lấy theo ký tự thứ 3 của mã thẻ: `1`, `2`, `5` → 100%; `3` → 95%; `4` → 80%. Không có thẻ hoặc thẻ sai định dạng (`^[A-Z]{2}[1-5]\d{12}$`) → 0%.

### R-05: Ghi audit log mọi lần truy cập bệnh án

Mọi lần xem, tạo, sửa bệnh án (cả HTML lẫn API) đều ghi audit log: người thực hiện, hành động, đối tượng, IP, thời điểm.

### R-06: Audit log bất biến

Audit log chỉ được thêm, không có chức năng sửa hay xóa. Chỉ ADMIN xem được.

### R-07: Mật khẩu và đăng nhập

Mật khẩu băm bằng Argon2id. Khóa tài khoản 15 phút sau 5 lần sai liên tiếp. Thông báo lỗi đăng nhập không tiết lộ tài khoản có tồn tại hay không.

### R-08: Session và CSRF

Cookie session có HttpOnly, SameSite=Lax, Secure ở môi trường production. Mọi request thay đổi dữ liệu phải có CSRF token. Đăng nhập thì tạo session mới.

### R-09: Quản lý secret

Secret chỉ đọc từ biến môi trường. Ứng dụng không khởi động nếu thiếu `SECRET_KEY` hợp lệ.

### R-10: Không rò rỉ thông tin qua lỗi và log

Không trả stack trace cho client. Không ghi PII (CCCD, mã BHYT, chẩn đoán, ghi chú, mật khẩu) vào log.

### R-11: Che định danh cá nhân

CCCD và mã BHYT được che, chỉ hiện 4 ký tự cuối, trừ với RECEPTIONIST, ADMIN và chính bệnh nhân đó.

### R-12: Tách biệt dữ liệu hành chính và lâm sàng

Lễ tân và Admin không xem nội dung bệnh án (chẩn đoán, ghi chú, đơn thuốc).

### R-13: Lịch hẹn hợp lệ

Không đặt lịch hẹn trong quá khứ. Một bác sĩ không có hai lịch hẹn còn hiệu lực trùng giờ. Bệnh nhân chỉ được hủy lịch của chính mình khi lịch đang ở trạng thái REQUESTED.

### R-14: Không tin đường dẫn và URL từ người dùng

Server không dùng đường dẫn file hay URL do người dùng cung cấp mà chưa đối chiếu với danh sách cho phép (allowlist).

### R-15: Không để lộ sự tồn tại của đối tượng

Đối tượng không tồn tại và đối tượng không có quyền truy cập đều trả về 404 giống hệt nhau.
