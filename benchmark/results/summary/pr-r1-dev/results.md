# Kết quả benchmark

Chấm theo spec mục 8.6. Ô có ± là trung bình ± độ lệch chuẩn qua các lần chạy; `-` là không xác định (không có dự đoán nào).

## Độ chính xác

Chặt: NEEDS_REVIEW tính là FP. Lỏng: bỏ qua NEEDS_REVIEW. TP, FN và recall như nhau ở hai cách.

| Cấu hình | LLM | Lần chạy | TP | FN | FP (chặt) | Precision (chặt) | Recall | F1 (chặt) | FP (lỏng) | F1 (lỏng) |
|---|---|---|---|---|---|---|---|---|---|---|
| C1 | — | 1 | 3.00 | 2.00 | 13.00 | 0.19 | 0.60 | 0.29 | 13.00 | 0.29 |
| C1+DAST | — | 1 | 3.00 | 2.00 | 13.00 | 0.19 | 0.60 | 0.29 | 13.00 | 0.29 |
| C2 | claude-mcp/claude-sonnet-5-5 | 1 | 5.00 | 0.00 | 3.00 | 0.62 | 1.00 | 0.77 | 1.00 | 0.91 |

## Recall theo nhóm lỗ hổng

| Cấu hình | category:logic | category:pattern | measured:neither | measured:sast_sca |
|---|---|---|---|---|
| C1 | 0.00 (n=2) | 1.00 (n=3) | 0.00 (n=2) | 1.00 (n=3) |
| C1+DAST | 0.00 (n=2) | 1.00 (n=3) | 0.00 (n=2) | 1.00 (n=3) |
| C2 | 1.00 (n=2) | 1.00 (n=3) | 1.00 (n=2) | 1.00 (n=3) |

`measured:sast_sca`: C1 bắt được; `measured:dast_only`: chỉ ZAP bắt được; `measured:neither`: không công cụ nào bắt được.

## Quyết định của quality gate (cấp PR) và các lần chạy

Phát hiện ZAP đã có trên bản gốc S00 (cùng rule ZAP) là vấn đề có sẵn của app đang chạy, không do PR gây ra: không tính TP hay FP, đếm ở cột riêng. "FP ở code có sẵn": số FP (chấm chặt, cộng mọi lần chạy) chỉ nằm trên dòng PR không thêm, trong file PR có sửa; đã tính trong cột FP ở trên.

| Cấu hình | PR có lỗ hổng bị chặn | PR sạch / mồi nhử được qua | FP trên PR sạch (mỗi lần chạy) | FP ở code có sẵn | Phát hiện DAST có sẵn | NEEDS_REVIEW | Lần chạy lỗi | Lần chạy dở dang |
|---|---|---|---|---|---|---|---|---|
| C1 | 2/4 | 1/2 | 1 | 9 | 0 | 0 | 0 | 0 |
| C1+DAST | 2/4 | 1/2 | 1 | 9 | 59 | 0 | 0 | 0 |
| C2 | 4/4 | 2/2 | 0 | 0 | 59 | 2 | 0 | 0 |

## Chi phí mỗi PR (trung bình, lần chạy thành công)

| Cấu hình | Thời gian agent (s) | Thời gian cả lượt (s) | Lượt gọi LLM | Lượt gọi công cụ | Token vào | Token ra | Chi phí quy đổi (USD) |
|---|---|---|---|---|---|---|---|
| C2 | 64.9 | 64.9 | 29.5 | 19.5 | 122801 | 10022 | 0.2061 |

## Từng lỗ hổng: số lần được phát hiện / số lần chạy

| Lỗ hổng | Nhóm | C1 | C1+DAST | C2 |
|---|---|---|---|---|
| S01-1 SQL injection qua tham số địa chỉ (area) ghép vào text() | pattern | 1/1 | 1/1 | 1/1 |
| S07-1 Tỷ lệ BHYT chi trả lấy từ form do client gửi, không tính từ mã thẻ | logic | 0/1 | 0/1 | 1/1 |
| S10-1 CronJob sao lưu chạy container bằng root (runAsUser 0) | pattern | 1/1 | 1/1 | 1/1 |
| S10-2 Bucket chứa bản sao lưu CSDL cho phép đọc công khai (Principal *) | pattern | 1/1 | 1/1 | 1/1 |
| S14-1 Kê đơn nhanh chỉ kiểm tra quyền xem bệnh án, y tá và bác sĩ không phụ trách kê được đơn | logic | 0/1 | 0/1 | 1/1 |

Phiên bản agent (hash cây `agent/`, có thay đổi chưa commit): C2: [['7c014a964c5f229ced789bf8e23c00265f2fc06d', False]]
