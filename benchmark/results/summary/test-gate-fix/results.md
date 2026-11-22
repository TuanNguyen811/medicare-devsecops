# Kết quả benchmark

Chấm theo spec gốc mục 5.3 và spec bổ sung mục 8.4. Ô có ± là trung bình ± độ lệch chuẩn qua các lần chạy; `-` là không xác định (không có dự đoán nào).

## Độ chính xác

Chặt: NEEDS_REVIEW tính là FP. Lỏng: bỏ qua NEEDS_REVIEW. TP, FN và recall như nhau ở hai cách.

| Cấu hình | LLM | Lần chạy | TP | FN | FP (chặt) | Precision (chặt) | Recall | F1 (chặt) | FP (lỏng) | F1 (lỏng) |
|---|---|---|---|---|---|---|---|---|---|---|
| C1 | — | 1 | 7.00 | 21.00 | 11.00 | 0.39 | 0.25 | 0.30 | 11.00 | 0.30 |
| C1+DAST | — | 1 | 7.00 | 21.00 | 11.00 | 0.39 | 0.25 | 0.30 | 11.00 | 0.30 |
| C2 | claude-mcp/claude-sonnet-5-5 | 3 | 25.33 ± 0.47 | 2.67 ± 0.47 | 3.33 ± 0.47 | 0.88 ± 0.01 | 0.90 ± 0.02 | 0.89 ± 0.00 | 2.33 ± 0.47 | 0.91 ± 0.00 |
| C3 | claude-mcp/claude-sonnet-5-5 | 1 | 28.00 | 0.00 | 5.00 | 0.85 | 1.00 | 0.92 | 2.00 | 0.97 |
| C4 | claude-mcp/claude-sonnet-5-5 | 1 | 24.00 | 4.00 | 7.00 | 0.77 | 0.86 | 0.81 | 4.00 | 0.86 |
| C5 | claude-mcp/claude-sonnet-5-5 | 1 | 25.00 | 3.00 | 3.00 | 0.89 | 0.89 | 0.89 | 2.00 | 0.91 |

## Recall theo nhóm lỗ hổng

| Cấu hình | category:logic | category:pattern | measured:neither | measured:sast_sca |
|---|---|---|---|---|
| C1 | 0.00 (n=16) | 0.58 (n=12) | 0.00 (n=21) | 1.00 (n=7) |
| C1+DAST | 0.00 (n=16) | 0.58 (n=12) | 0.00 (n=21) | 1.00 (n=7) |
| C2 | 0.83 (n=48) | 1.00 (n=36) | 0.87 (n=63) | 1.00 (n=21) |
| C3 | 1.00 (n=16) | 1.00 (n=12) | 1.00 (n=21) | 1.00 (n=7) |
| C4 | 0.75 (n=16) | 1.00 (n=12) | 0.81 (n=21) | 1.00 (n=7) |
| C5 | 0.81 (n=16) | 1.00 (n=12) | 0.86 (n=21) | 1.00 (n=7) |

`measured:sast_sca`: C1 bắt được; `measured:dast_only`: chỉ ZAP bắt được; `measured:neither`: không công cụ nào bắt được.

## Quyết định của quality gate (cấp PR) và các lần chạy

Phát hiện ZAP đã có trên bản gốc S00 (cùng rule ZAP) là vấn đề có sẵn của app đang chạy, không do PR gây ra: không tính TP hay FP, đếm ở cột riêng. "FP ở code có sẵn": số FP (chấm chặt, cộng mọi lần chạy) chỉ nằm trên dòng PR không thêm, trong file PR có sửa; đã tính trong cột FP ở trên.

| Cấu hình | PR có lỗ hổng bị chặn | PR sạch / mồi nhử được qua | FP trên PR sạch (mỗi lần chạy) | FP ở code có sẵn | Phát hiện DAST có sẵn | NEEDS_REVIEW | Lần chạy lỗi | Lần chạy dở dang |
|---|---|---|---|---|---|---|---|---|
| C1 | 8/20 | 3/4 | 4 | 0 | 0 | 0 | 0 | 0 |
| C1+DAST | 8/20 | 3/4 | 4 | 0 | 227 | 0 | 0 | 0 |
| C2 | 53/60 | 11/12 | 0, 0, 1 | 0 | 671 | 13 | 0 | 0 |
| C3 | 19/20 | 3/4 | 2 | 0 | 159 | 70 | 0 | 0 |
| C4 | 18/20 | 4/4 | 1 | 0 | 218 | 12 | 0 | 0 |
| C5 | 18/20 | 4/4 | 0 | 0 | 227 | 1 | 0 | 0 |

## Chi phí mỗi PR (trung bình, lần chạy thành công)

| Cấu hình | Thời gian agent (s) | Thời gian cả lượt (s) | Lượt gọi LLM | Lượt gọi công cụ | Token vào | Token ra | Chi phí quy đổi (USD) |
|---|---|---|---|---|---|---|---|
| C2 | 45.6 | 46.7 | 19.8 | 15.4 | 104707 | 6678 | 0.1288 |
| C3 | 40.1 | 41.0 | 10.7 | 12.3 | 66050 | 6290 | 0.2024 |
| C4 | 46.3 | 47.3 | 22.1 | 16.1 | 95845 | 7315 | 0.1559 |
| C5 | 43.2 | 44.2 | 20.4 | 15.5 | 109751 | 6617 | 0.1606 |

## Từng lỗ hổng: số lần được phát hiện / số lần chạy

| Lỗ hổng | Nhóm | C1 | C1+DAST | C2 | C3 | C4 | C5 |
|---|---|---|---|---|---|---|---|
| S02-1 Xuất bệnh án tải phiếu khám theo id mà không kiểm tra policy.can_view_record (IDOR) | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S02-2 Tham số letterhead ghép thẳng vào thư mục tiêu đề in rồi đọc file, không đối chiếu danh sách cho phép (path traversal) | pattern | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S03-1 Token JWT của API di động được giải mã với verify_signature=False, ai cũng giả mạo được token của người khác | pattern | 1/1 | 1/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S03-2 Khóa ký JWT viết cứng trong mã nguồn thay vì đọc từ biến môi trường | pattern | 1/1 | 1/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S04-1 File YAML tải lên được giải tuần tự bằng yaml.load với yaml.Loader (không an toàn), cho phép thực thi mã | pattern | 1/1 | 1/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S04-2 File XML tải lên được phân tích bằng lxml với resolve_entities=True, thực thể ngoài được nạp (XXE) | pattern | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S05-1 Mẫu in do bác sĩ nhập được dựng bằng jinja2 Environment thường (không sandbox) qua from_string, dẫn tới SSTI và thực thi mã trên server | pattern | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S06-1 Ghi chú HTML của bác sĩ được lưu nguyên văn và hiển thị bằng |safe, không lọc thẻ (stored XSS) | pattern | 1/1 | 1/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S08-1 API key và secret key của tổng đài SMS ghi cứng trong mã nguồn | pattern | 1/1 | 1/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S09-1 Server tải URL kết quả xét nghiệm do người dùng nhập, chỉ kiểm tra scheme, không đối chiếu allowlist máy chủ xét nghiệm (SSRF) | pattern | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S11-1 Ghim PyYAML 5.3.1 có CVE-2020-14343 (FullLoader cho phép thực thi mã) và gọi yaml.full_load trên file bảng giá tải lên | pattern | 1/1 | 1/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S12-1 Sự kiện xem/sửa bệnh án ghi CCCD, mã BHYT và chẩn đoán vào log ứng dụng | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S12-2 Tác vụ dọn nhật ký xóa các bản ghi VIEW_RECORD lặp lại, làm mất dấu vết truy cập bệnh án | logic | 0/1 | 0/1 | 3/3 | 1/1 | 0/1 | 1/1 |
| S13-1 Lỗi khi kiểm tra phiên (ví dụ giá trị ca làm việc tự gửi lúc đăng nhập) thì vẫn cho qua với người dùng của phiên, bỏ qua kiểm tra hạn phiên, session_version và is_active | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S15-1 SQL injection qua tham số period ghép vào date_trunc() trong câu SQL thống kê | pattern | 1/1 | 1/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S16-1 Quyền đổi lịch hẹn của bệnh nhân không kiểm tra lịch có thuộc về bệnh nhân đó | logic | 0/1 | 0/1 | 0/3 | 1/1 | 1/1 | 0/1 |
| S17-1 Mass assignment khi tự sửa hồ sơ: mọi trường gửi lên (role, department_id, patient_id…) được gán thẳng vào tài khoản, người dùng tự nâng quyền thành ADMIN | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S18-1 Kiểm tra trùng giờ rồi mới chèn lịch hẹn, không khóa và đã bỏ ràng buộc CSDL: hai yêu cầu đồng thời đặt được cùng một giờ của bác sĩ (race condition) | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S19-1 Khoa lấy từ tham số department_id của client, y tá xem được danh sách bệnh nhân khoa khác | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S20-1 Số lượng dòng dịch vụ không kiểm tra số nguyên dương, số lượng âm làm giảm tổng hóa đơn | logic | 0/1 | 0/1 | 1/3 | 1/1 | 0/1 | 0/1 |
| S20-2 Trạng thái hóa đơn lấy từ request, cho phép chuyển ngược PAID về UNPAID ngoài luồng UNPAID → PAID | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S21-1 Token đặt lại mật khẩu không hết hạn và không bị hủy sau khi dùng, dùng lại được nhiều lần | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S21-2 Phản hồi yêu cầu đặt lại mật khẩu khác nhau tùy email có tài khoản hay không (dò tài khoản) | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S22-1 Xuất CSV không trung hòa ô bắt đầu bằng = + - @ tab hoặc xuống dòng (chèn công thức) | pattern | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S22-2 Bác sĩ và y tá được xuất danh sách bệnh nhân, file chứa CCCD và mã BHYT đầy đủ không che | logic | 0/1 | 0/1 | 3/3 | 1/1 | 0/1 | 1/1 |
| S23-1 Bác sĩ tự gán mình làm bác sĩ phụ trách cho bất kỳ bệnh nhân nào (kể cả khoa khác), từ đó đọc và sửa được bệnh án | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S24-1 Trình duyệt có cookie ghi nhớ đăng nhập (của bất kỳ tài khoản nào) đoán mật khẩu không giới hạn, không bị khóa sau 5 lần sai | logic | 0/1 | 0/1 | 3/3 | 1/1 | 1/1 | 1/1 |
| S24-2 Đăng xuất chỉ xóa cookie ghi nhớ ở trình duyệt, token vẫn còn hiệu lực ở server nên bản sao cookie vẫn đăng nhập được | logic | 0/1 | 0/1 | 0/3 | 1/1 | 0/1 | 0/1 |

Phiên bản agent (hash cây `agent/`, có thay đổi chưa commit): C2: [['8f85d858ccdef9e6eb0b35f4f77c6d71b58d5e47', False]]; C3: [['8f85d858ccdef9e6eb0b35f4f77c6d71b58d5e47', False]]; C4: [['8f85d858ccdef9e6eb0b35f4f77c6d71b58d5e47', False]]; C5: [['8f85d858ccdef9e6eb0b35f4f77c6d71b58d5e47', False]]
