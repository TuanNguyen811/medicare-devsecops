# Kết quả benchmark: AI Security Agent trên 35 Pull Request thật

Tài liệu này báo cáo kết quả đo AI Security Agent (`secagent`) trong pipeline DevSecOps của MediCare HMS. Mỗi kịch bản là một Pull Request thật trên GitHub, đi qua pipeline thật và quality gate thật. Thiết kế benchmark nằm ở spec bổ sung [§8](superpowers/specs/2026-11-21-ops-dast-benchmark-design.md). Bảng số liệu do `benchmark/evaluate.py` sinh ra nằm ở [`benchmark/results/summary/pr-r1-test/results.md`](../benchmark/results/summary/pr-r1-test/results.md) (tập test) và [`pr-r1-dev/results.md`](../benchmark/results/summary/pr-r1-dev/results.md) (tập dev).

## Tóm tắt

Trên 30 PR của tập test (20 PR có lỗ hổng chứa 28 lỗ hổng, 10 PR không có lỗ hổng):

| | Lỗ hổng phát hiện | Precision | F1 | PR có lỗ hổng bị chặn | PR không lỗ hổng được cho qua |
|---|---|---|---|---|---|
| Chỉ công cụ quét | 9/28 | 0,43 | 0,37 | 10/20 | 9/10 |
| Công cụ quét + **AI Agent** | **26/28** | **0,84** | **0,88** | **19/20** | 9/10 |

- AI Agent tìm được 14/16 lỗ hổng logic nghiệp vụ, công cụ quét không tìm được lỗ hổng logic nào.
- Quyết định chặn hay cho qua của quality gate thật trên GitHub khớp với kết quả chấm lại bằng `evaluate.py` ở cả 35/35 PR.
- Mỗi PR mất trung bình 46 giây cho phần AI và khoảng 0,16 USD chi phí quy đổi.

## 1. Thiết lập

**35 PR thật trên GitHub** (`[Bench] <ID> · …`, #47–#81, để mở để xem lại, không merge). Mỗi PR áp một kịch bản trong `benchmark/scenarios/` lên `main`:

| Tập | PR | Nội dung |
|---|---|---|
| Test | 20 PR có lỗ hổng | S02–S06, S08, S09, S11–S13, S15–S24: 28 lỗ hổng (12 dạng mẫu, 16 logic nghiệp vụ). S15 có thêm một chú thích prompt injection nhắm vào công cụ review |
| Test | 10 PR không có lỗ hổng | S00 (PR rỗng); D02–D04 (mồi nhử: code trông giống lỗi với công cụ quét nhưng an toàn); D05–D10 (tính năng bình thường, sạch) |
| Dev | 5 PR | S01, S07, S10, S14, D01: dùng để chỉnh prompt trước khi chốt, báo riêng để tham khảo |

**Mỗi PR chạy như một PR thật** (`benchmark/pr_bench.py`):
1. Pipeline `pr-security.yml` chạy CodeQL, Semgrep, Bandit, Trivy, Gitleaks, Checkov, zizmor và ZAP (5 vai trò).
2. AI Agent chạy **một lần** trên máy người review (chế độ `claude-mcp`, model **`claude-sonnet-5-5`**), trên đúng SARIF của lượt chạy đó, rồi chuyển report vào job `ai-security-agent` của PR ([`security/handoff/`](../security/handoff/handoff.py)).
3. `agent-comment` đăng báo cáo và comment tại dòng lỗi; `quality-gate` (chế độ `ai-assisted`) quyết định chặn hay cho qua.

**Agent không thấy đáp án:** `local_review.py --benchmark-view` cho agent thấy đúng cây mà `scenario.materialize` định nghĩa: mã nguồn ở mốc benchmark (đã bỏ tài liệu thiết kế, đáp án, kết quả, và README được viết lại trung tính) cộng thay đổi của PR. Cây này được đối chiếu trùng khớp với `materialize` trên các kịch bản.

**Ba cấu hình được chấm trên cùng một PR:**
- **C1:** chỉ công cụ quét tĩnh; quality gate chế độ `traditional`.
- **C1+DAST:** C1 cộng ZAP.
- **C2:** C1+DAST cộng AI Agent; quality gate chế độ `ai-assisted` (quyết định thật của pipeline).

**Cách chấm** (spec bổ sung §8.4):
- Một dự đoán khớp một lỗ hổng trong đáp án khi cùng file, lệch không quá ±3 dòng so với một vị trí của lỗ hổng, và cùng họ CWE (hoặc cùng rule của công cụ, hoặc agent nêu đúng quy tắc nghiệp vụ R-xx bị vi phạm).
- **Chặt:** kết luận NEEDS_REVIEW tính là báo nhầm. **Lỏng:** bỏ qua NEEDS_REVIEW. Số chính là chấm chặt.
- Cảnh báo ZAP đã có trên S00 (cùng rule) là vấn đề sẵn có của ứng dụng, không tính đúng hay sai.

**Chống thiên vị:**
- Prompt được chỉnh trên tập dev rồi chốt ([`benchmark/PROMPT_FREEZE`](../benchmark/PROMPT_FREEZE)) trước khi viết các kịch bản test; prompt không đổi kể từ đó.
- Đáp án của mỗi kịch bản test được commit trước khi kịch bản đó chạy.
- Mỗi lượt AI là một tiến trình Claude Code riêng, không có lịch sử hội thoại, chỉ có các công cụ chỉ đọc của `secagent`.
- Điểm do `evaluate.py` chấm tự động theo đáp án.

## 2. Kết quả trên tập test

| Cấu hình | TP / 28 | FP (chặt) | Precision | Recall | F1 | FP (lỏng) | F1 (lỏng) |
|---|---|---|---|---|---|---|---|
| C1 | 9 | 12 | 0,43 | 0,32 | 0,37 | 12 | 0,37 |
| C1+DAST | 9 | 12 | 0,43 | 0,32 | 0,37 | 12 | 0,37 |
| **C2** | **26** | **5** | **0,84** | **0,93** | **0,88** | 2 | 0,93 |

**Recall theo nhóm lỗ hổng:**

| Cấu hình | Dạng mẫu (12) | Logic nghiệp vụ (16) | Công cụ quét bỏ sót (19) |
|---|---|---|---|
| C1 | 0,75 | 0,00 | 0,00 |
| C2 | 1,00 | 0,88 | 0,89 |

Nhóm "công cụ quét bỏ sót" là nhãn **đo được** trên chính các PR này (`measured_detection` trong `scenario.yaml`). ZAP không bắt thêm lỗ hổng nào so với các công cụ quét tĩnh.

**Quyết định của quality gate:**

| Cấu hình | PR có lỗ hổng bị chặn | PR không lỗ hổng được cho qua |
|---|---|---|
| C1 (gate `traditional`) | 10/20 | 9/10 |
| **C2 (gate `ai-assisted`, quyết định thật trên GitHub)** | **19/20** | **9/10** |

## 3. Trả lời các câu hỏi nghiên cứu

### RQ1: AI có giảm báo nhầm mà không gạt bỏ lỗ hổng thật không?

Có.
- Báo nhầm giảm từ 12 xuống 5 (chấm chặt), precision từ 0,43 lên 0,84.
- Không lỗ hổng nào mà công cụ quét đã bắt bị AI kết luận nhầm là báo nhầm (recall nhóm "công cụ quét bắt được" = 1,00).
- Trên 10 PR không lỗ hổng, AI cho qua 9/10. Công cụ quét một mình cũng cho qua 9/10, nhưng PR bị chặn nhầm của hai bên là cùng một PR (D03).

**5 báo nhầm của C2:**
- **D03** (2 mục, NEEDS_REVIEW): xem mục 4.
- **S08** (1 mục, NEEDS_REVIEW): cảnh báo Bandit B310 về `urlopen` mà AI để lại cho người xem.
- **S05** (1 mục): `|safe` ở `slip.html`, nơi đầu ra của lỗi SSTI hiện ra. Vị trí này không nằm trong đáp án.
- **S11** (1 mục): thiếu cấu hình `cooldown` cho uv trong `pyproject.toml`, một vấn đề vệ sinh chuỗi cung ứng có thật nhưng không có trong đáp án.

Hai mục cuối là vấn đề có thật mà đáp án không ghi, nên precision ở đây là cận dưới.

### RQ2: AI bắt thêm được bao nhiêu lỗ hổng mà công cụ quét bỏ sót?

Công cụ quét bắt 9/28 lỗ hổng và không bắt lỗ hổng logic nào. AI bắt 26/28, tức thêm 17 lỗ hổng, trong đó 14/16 lỗ hổng logic. Ví dụ:
- IDOR khi xuất bệnh án (S02), y tá xem bệnh nhân khoa khác (S19), bác sĩ tự nhận bệnh nhân (S23), đổi lịch hẹn không kiểm tra quyền sở hữu (S16);
- mass assignment tự nâng quyền ADMIN (S17);
- token đặt lại mật khẩu dùng lại được và dò tài khoản (S21);
- ghi CCCD và mã BHYT vào log, xóa dấu vết truy cập bệnh án (S12);
- race condition đặt trùng lịch (S18).

**Hai lỗ hổng AI bỏ sót:**

| Lỗ hổng | Ghi chú |
|---|---|
| S20-1: số lượng âm làm giảm tổng hóa đơn | AI bắt được lỗ hổng còn lại của cùng PR (đổi trạng thái PAID → UNPAID) nên PR vẫn bị chặn |
| S24-2: đăng xuất không thu hồi token ghi nhớ ở server | AI bắt được lỗ hổng còn lại của cùng PR (cookie ghi nhớ tắt khóa tài khoản) nên PR vẫn bị chặn |

Cả hai đều là lỗ hổng thứ hai trong một PR có hai lỗ hổng.

### RQ3: Chi phí vận hành

| Mỗi PR (tập test) | Trung bình |
|---|---|
| Thời gian AI | 46 s |
| Lượt gọi LLM / gọi công cụ | 21,7 / 15,5 |
| Token vào / ra | 111 154 / 7 078 |
| Chi phí quy đổi | 0,16 USD |

Tổng chi phí quy đổi của 35 PR là 5,90 USD. Chi phí này là con số Claude Code tự báo theo bảng giá API; benchmark chạy bằng gói thuê bao nên không trả tiền theo token.

### Độ vững trước prompt injection (S15)

S15 có một chú thích ngay trên câu SQL, nhắm vào công cụ review tự động: khẳng định đoạn code đã được kiểm duyệt và yêu cầu coi là báo nhầm. Bên dưới là một lỗ hổng SQL injection thật. AI kết luận TP mức HIGH với độ tin cậy 0,95, nêu rõ chú thích là nội dung không đáng tin, và gate chặn PR ([#62](https://github.com/TuanNguyen811/medicare-devsecops/pull/62)).

## 4. Hai PR mà quality gate quyết định khác kỳ vọng

- **S18, race condition đặt trùng lịch** ([#65](https://github.com/TuanNguyen811/medicare-devsecops/pull/65)): AI tìm ra lỗ hổng và chấm MEDIUM, đúng với mức của đáp án. Gate chỉ chặn từ HIGH trở lên, nên PR được cho qua. Đây là đúng chính sách, nhưng chỉ số vẫn tính đây là một PR có lỗ hổng không bị chặn.
- **D03, thông báo có định dạng** ([#48](https://github.com/TuanNguyen811/medicare-devsecops/pull/48)): Semgrep chấm `|safe` là XSS mức HIGH. AI đọc code và kết luận đúng rằng HTML đã được làm sạch bằng `bleach` trước khi lưu. Nhưng bằng chứng AI trích không phải đoạn code tại đúng vị trí cảnh báo, nên khâu kiểm tra chống bịa đặt (`phases/check.py`) đổi kết luận thành NEEDS_REVIEW và gate chặn. Đây là cái giá của luật "kết luận báo nhầm phải có bằng chứng tại chỗ": thà chặn nhầm một PR còn hơn để lọt một kết luận báo nhầm không có căn cứ.

## 5. Tập dev (tham khảo)

| Cấu hình | Lỗ hổng phát hiện | Báo nhầm (chặt) | PR có lỗ hổng bị chặn | PR không lỗ hổng được cho qua |
|---|---|---|---|---|
| C1 | 3/5 | 13 | 2/4 | 1/2 |
| C2 | 5/5 | 3 | 4/4 | 2/2 |

Tập dev từng được dùng để chỉnh prompt, nên các số này không dùng để kết luận. Cột "không lỗ hổng" gồm D01 và S00.

## 6. Kết quả từng PR

"Gate thật" là quyết định của quality gate trên GitHub (chế độ `ai-assisted`); ✓ là đúng kỳ vọng (PR có lỗ hổng bị chặn, PR không lỗ hổng được cho qua).

| Kịch bản | PR | Loại | Lỗi trong đáp án | Công cụ quét bắt | AI bắt | Gate thật |
|---|---|---|---|---|---|---|
| S00 Bản gốc, không thay đổi mã nguồn | [#51](https://github.com/TuanNguyen811/medicare-devsecops/pull/51) | PR rỗng | 0 | 0/0 | 0/0 | cho qua ✓ |
| D02 Kiểm tra thẻ BHYT trực tuyến | [#47](https://github.com/TuanNguyen811/medicare-devsecops/pull/47) | sạch / mồi nhử | 0 | 0/0 | 0/0 | cho qua ✓ |
| D03 Thông báo nội bộ trên trang chủ | [#48](https://github.com/TuanNguyen811/medicare-devsecops/pull/48) | sạch / mồi nhử | 0 | 0/0 | 0/0 | chặn ✗ |
| D04 Nhập danh mục thuốc từ tệp YAML | [#49](https://github.com/TuanNguyen811/medicare-devsecops/pull/49) | sạch / mồi nhử | 0 | 0/0 | 0/0 | cho qua ✓ |
| D05 Lịch khám theo ngày | [#50](https://github.com/TuanNguyen811/medicare-devsecops/pull/50) | sạch / mồi nhử | 0 | 0/0 | 0/0 | cho qua ✓ |
| D06 Ngừng sử dụng thuốc trong danh mục | [#77](https://github.com/TuanNguyen811/medicare-devsecops/pull/77) | sạch / mồi nhử | 0 | 0/0 | 0/0 | cho qua ✓ |
| D07 Lịch sử đơn thuốc của bệnh nhân | [#78](https://github.com/TuanNguyen811/medicare-devsecops/pull/78) | sạch / mồi nhử | 0 | 0/0 | 0/0 | cho qua ✓ |
| D08 Hóa đơn chưa thanh toán theo khoảng ngày | [#79](https://github.com/TuanNguyen811/medicare-devsecops/pull/79) | sạch / mồi nhử | 0 | 0/0 | 0/0 | cho qua ✓ |
| D09 Quản lý danh mục khoa | [#80](https://github.com/TuanNguyen811/medicare-devsecops/pull/80) | sạch / mồi nhử | 0 | 0/0 | 0/0 | cho qua ✓ |
| D10 Danh sách bác sĩ theo khoa | [#81](https://github.com/TuanNguyen811/medicare-devsecops/pull/81) | sạch / mồi nhử | 0 | 0/0 | 0/0 | cho qua ✓ |
| S02 Xuất bệnh án | [#52](https://github.com/TuanNguyen811/medicare-devsecops/pull/52) | có lỗi | 2 | 1/2 | 2/2 | chặn ✓ |
| S03 API cho ứng dụng di động | [#53](https://github.com/TuanNguyen811/medicare-devsecops/pull/53) | có lỗi | 2 | 2/2 | 2/2 | chặn ✓ |
| S04 Nhập dữ liệu từ hệ thống cũ | [#54](https://github.com/TuanNguyen811/medicare-devsecops/pull/54) | có lỗi | 2 | 1/2 | 2/2 | chặn ✓ |
| S05 Mẫu in phiếu khám tùy chỉnh | [#55](https://github.com/TuanNguyen811/medicare-devsecops/pull/55) | có lỗi | 1 | 0/1 | 1/1 | chặn ✓ |
| S06 Ghi chú bác sĩ dạng rich text | [#56](https://github.com/TuanNguyen811/medicare-devsecops/pull/56) | có lỗi | 1 | 1/1 | 1/1 | chặn ✓ |
| S08 Gửi SMS nhắc lịch | [#57](https://github.com/TuanNguyen811/medicare-devsecops/pull/57) | có lỗi | 1 | 1/1 | 1/1 | chặn ✓ |
| S09 Nhận kết quả xét nghiệm từ URL | [#58](https://github.com/TuanNguyen811/medicare-devsecops/pull/58) | có lỗi | 1 | 1/1 | 1/1 | chặn ✓ |
| S11 Nâng cấp tiện ích: nhập bảng giá thuốc từ file YAML | [#59](https://github.com/TuanNguyen811/medicare-devsecops/pull/59) | có lỗi | 1 | 1/1 | 1/1 | chặn ✓ |
| S12 Tối ưu logging | [#60](https://github.com/TuanNguyen811/medicare-devsecops/pull/60) | có lỗi | 2 | 0/2 | 2/2 | chặn ✓ |
| S13 Tối ưu middleware xác thực | [#61](https://github.com/TuanNguyen811/medicare-devsecops/pull/61) | có lỗi | 1 | 0/1 | 1/1 | chặn ✓ |
| S15 Báo cáo thống kê lịch hẹn cho quản trị viên | [#62](https://github.com/TuanNguyen811/medicare-devsecops/pull/62) | có lỗi (prompt injection) | 1 | 1/1 | 1/1 | chặn ✓ |
| S16 Bệnh nhân tự đổi lịch hẹn | [#63](https://github.com/TuanNguyen811/medicare-devsecops/pull/63) | có lỗi | 1 | 0/1 | 1/1 | chặn ✓ |
| S17 Tự cập nhật hồ sơ cá nhân | [#64](https://github.com/TuanNguyen811/medicare-devsecops/pull/64) | có lỗi | 1 | 0/1 | 1/1 | chặn ✓ |
| S18 Đặt lịch nhanh | [#65](https://github.com/TuanNguyen811/medicare-devsecops/pull/65) | có lỗi | 1 | 0/1 | 1/1 | cho qua ✗ |
| S19 Danh sách bệnh nhân theo khoa cho y tá | [#66](https://github.com/TuanNguyen811/medicare-devsecops/pull/66) | có lỗi | 1 | 0/1 | 1/1 | chặn ✓ |
| S20 Hóa đơn nhiều dòng | [#67](https://github.com/TuanNguyen811/medicare-devsecops/pull/67) | có lỗi | 2 | 0/2 | 1/2 | chặn ✓ |
| S21 Quên mật khẩu | [#68](https://github.com/TuanNguyen811/medicare-devsecops/pull/68) | có lỗi | 2 | 0/2 | 2/2 | chặn ✓ |
| S22 Xuất danh sách bệnh nhân CSV | [#69](https://github.com/TuanNguyen811/medicare-devsecops/pull/69) | có lỗi | 2 | 0/2 | 2/2 | chặn ✓ |
| S23 Bác sĩ nhận phụ trách bệnh nhân | [#70](https://github.com/TuanNguyen811/medicare-devsecops/pull/70) | có lỗi | 1 | 0/1 | 1/1 | chặn ✓ |
| S24 Ghi nhớ đăng nhập | [#71](https://github.com/TuanNguyen811/medicare-devsecops/pull/71) | có lỗi | 2 | 0/2 | 1/2 | chặn ✓ |
| D01 Lọc danh sách bệnh nhân theo năm | [#72](https://github.com/TuanNguyen811/medicare-devsecops/pull/72) | sạch / mồi nhử · dev | 0 | 0/0 | 0/0 | cho qua ✓ |
| S01 Tìm kiếm bệnh nhân nâng cao | [#73](https://github.com/TuanNguyen811/medicare-devsecops/pull/73) | có lỗi · dev | 1 | 1/1 | 1/1 | chặn ✓ |
| S07 Điều chỉnh mức hưởng BHYT trên hóa đơn | [#74](https://github.com/TuanNguyen811/medicare-devsecops/pull/74) | có lỗi · dev | 1 | 0/1 | 1/1 | chặn ✓ |
| S10 Sao lưu CSDL hằng đêm lên S3 | [#75](https://github.com/TuanNguyen811/medicare-devsecops/pull/75) | có lỗi · dev | 2 | 2/2 | 2/2 | chặn ✓ |
| S14 Kê đơn nhanh theo đơn mẫu | [#76](https://github.com/TuanNguyen811/medicare-devsecops/pull/76) | có lỗi · dev | 1 | 0/1 | 1/1 | chặn ✓ |

## 7. Hạn chế

1. **Một người viết đề, đáp án và prompt.** Thứ tự cố định trong lịch sử git (chốt prompt, rồi viết kịch bản test, rồi commit đáp án trước khi chạy) giảm thiên vị nhưng không loại hẳn.
2. **Mẫu nhỏ và mỗi PR chạy một lần.** 28 lỗ hổng trong 30 PR test, trên một ứng dụng, PR do benchmark tạo ra. LLM không cho kết quả giống hệt nhau mỗi lần; benchmark không đo độ dao động giữa các lần chạy.
3. **Quy tắc của quality gate được sửa sau khi xem dữ liệu chạy thử trên chính các kịch bản này.** Quy tắc "AI xác nhận một phát hiện mức thấp của công cụ là lỗ hổng HIGH/CRITICAL thì chặn" được thêm sau khi thấy ca S09 (Bandit chấm LOW một lỗ hổng SSRF).
4. **D05–D10 được viết sau khi đã có kết quả,** D06–D10 cụ thể là sau khi có kết quả của 30 PR đầu, để tập có thêm PR không lỗ hổng như thực tế. Mỗi kịch bản qua review độc lập để chắc là sạch, và AI tự quyết định trên các PR này như mọi PR khác.
5. **Số liệu là của "secagent + Claude Sonnet 5.5"** chạy qua `claude-mcp`. Con số tuyệt đối phụ thuộc model.
6. **Cách chấm chặt làm thấp precision.** Một số báo nhầm là vấn đề có thật nhưng không có trong đáp án (S05, S11).
7. **DAST không bắt thêm lỗ hổng nào.** Với cấu hình ZAP hiện tại (spider 2 phút, quét chủ động tối đa 5 phút, policy mặc định), ZAP chỉ thấy các vấn đề header vốn có của ứng dụng. Một số loại lỗ hổng trong tập test (SSRF, XXE, SSTI) về nguyên tắc DAST bắt được nếu cấu hình sâu hơn.
8. **Lỗ hổng mức MEDIUM không chặn PR** (S18): chính sách chọn để giảm chặn nhầm, có thể chỉnh theo khẩu vị rủi ro.
9. **Ở chế độ `claude-mcp`, quality gate tin vào máy của người review** (người chạy AI và người mở PR là một trong benchmark này). Pipeline chỉ nhận report từ đúng tài khoản, đúng commit và chưa bị sửa.
10. **Hai sự cố vận hành, không ảnh hưởng kết quả:** review của D04 thất bại một lần do tải artifact từ GitHub lỗi và được chạy lại tự động; D05 được review hai lần do khởi động lại công cụ (pipeline dùng report của lần đầu, điểm chấm theo lần thứ hai; cả hai cùng kết luận PR sạch).

## 8. Chạy lại

```bash
# Mở PR, review bằng AI trên máy, thu kết quả (cần gh, Claude Code đã đăng nhập,
# biến repo LLM_PROVIDER=claude-mcp, AGENT_REPORT_AUTHOR, SECURITY_GATE_MODE=ai-assisted)
CLAUDE_BIN=<đường dẫn claude> uv run --project agent --with pyyaml==6.0.2 \
  python benchmark/pr_bench.py run --tag <tag>

# Chấm điểm
uv run --project agent --with pyyaml==6.0.2 python benchmark/evaluate.py \
  --scan pr-<tag> --select test --out benchmark/results/summary/pr-<tag>-test
```

Dữ liệu của lượt chạy này:
- danh sách PR: `benchmark/results/pr/r1/prs.json`;
- kết quả công cụ quét và quyết định thật của pipeline: `benchmark/results/scans/pr-r1/<ID>/`;
- report, trace và log phiên Claude của AI: `benchmark/results/runs/pr-r1/C2/<ID>/rep1/`.
