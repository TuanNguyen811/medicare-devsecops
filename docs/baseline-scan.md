# Kết quả quét bản sạch (mốc FP cho thực nghiệm)

**Đối tượng quét:**
- `app/`: giống hệt tag `v0.1-baseline`.
- `infra/terraform`, `infra/k8s`, `security/`, `.github/workflows`: thêm ở kế hoạch B.

Cây đầy đủ này được gắn tag **`v0.2-baseline`** khi merge kế hoạch B. Mọi patch kịch bản benchmark sẽ áp lên tag đó.

**Công cụ:** dùng đúng phiên bản trong [`security/tool-versions.env`](../security/tool-versions.env).
- Semgrep 1.184.0 (bộ rule `p/python`, `p/owasp-top-ten` và rule tùy chỉnh `security/semgrep/medicare.yml`)
- Bandit 1.9.4
- CodeQL `security-extended` (codeql-action v4.39.3)
- Trivy 0.76.2
- Gitleaks 8.30.1
- Checkov 3.4.3
- zizmor 1.32.0

**Cách chạy:**
- Mọi công cụ trừ CodeQL: `bash security/scan-local.sh <out-dir>`, chạy bằng Docker trên bản export các file đã commit.
- CodeQL: lấy artifact `sarif-main` của lần chạy `main-ci` số 42357471271.
- Mức độ được quy đổi bằng [`security/gate/gate.py`](../security/gate/gate.py), theo đúng logic mà quality gate dùng trên CI.

Ngày quét: 2026-11-07.

## Tổng hợp

| Công cụ | LOW | MEDIUM | HIGH | CRITICAL | Tổng |
|---|---|---|---|---|---|
| Semgrep | 0 | 0 | 0 | 0 | **0** |
| Bandit | 2 | 0 | 0 | 0 | **2** |
| CodeQL | 0 | 0 | 1 | 0 | **1** |
| Trivy (SCA) | 0 | 0 | 0 | 0 | **0** |
| Gitleaks | 0 | 0 | 2 | 0 | **2** |
| Checkov (IaC) | 0 | 0 | 10 | 0 | **10** |
| zizmor (workflow CI) | 0 | 0 | 0 | 0 | **0** |
| **Tổng** | 2 | 0 | 13 | 0 | **15** |

Nếu chạy quality gate chế độ `traditional` trên toàn bộ cây thì kết quả là **CHẶN**, với 13 phát hiện mức HIGH.

Vì `main` là bản sạch đã qua review độc lập, **cả 15 phát hiện đều được coi là báo nhầm (FP) hoặc rủi ro chấp nhận được**. Đây là dữ liệu đầu vào để đo khả năng của AI Agent trong việc loại FP (RQ1).

## Chi tiết từng phát hiện

| # | Công cụ | Rule | Vị trí | Mức | Nhận định |
|---|---|---|---|---|---|
| 1 | Bandit | B101 `assert_used` | `app/medicare/common/errors.py:40` | LOW | FP về bảo mật. `assert isinstance(...)` chỉ để thu hẹp kiểu trong exception handler; nếu bị bỏ khi chạy `-O` thì cũng không mở ra đường khai thác nào |
| 2 | Bandit | B311 `random` | `app/medicare/seed.py:80` | LOW | FP. `random.Random(42)` chỉ dùng sinh dữ liệu demo cố định, không dùng cho mục đích mật mã |
| 3 | CodeQL | `py/clear-text-logging-sensitive-data` | `app/medicare/seed.py:212` | HIGH | FP. Luồng dữ liệu bị cho là đi từ biến `password` sang `print(counts)`, nhưng `counts` chỉ là số lượng bản ghi, không chứa mật khẩu |
| 4 | Gitleaks | `generic-api-key` | `app/tests/test_admin.py:9` | HIGH | FP. Mật khẩu giả trong test (`NEW_PASSWORD`), không phải secret thật |
| 5 | Gitleaks | `generic-api-key` | `app/tests/test_hardening.py:107` | HIGH | FP. Mật khẩu giả trong dữ liệu form của test |
| 6 | Checkov | `CKV_AWS_356` | `infra/terraform/main.tf:15` | HIGH | FP. Key policy mặc định của KMS (root của tài khoản có `kms:*`) là khuyến nghị chuẩn của AWS, để tránh khóa key không còn ai quản lý được |
| 7 | Checkov | `CKV_AWS_109` | `infra/terraform/main.tf:15` | HIGH | FP, cùng nguyên nhân với #6 |
| 8 | Checkov | `CKV_AWS_111` | `infra/terraform/main.tf:15` | HIGH | FP, cùng nguyên nhân với #6 |
| 9 | Checkov | `CKV_AWS_394` | `infra/terraform/main.tf:5` | HIGH | Chấp nhận được. Data source AZ không cố định danh sách zone; không ảnh hưởng bảo mật |
| 10 | Checkov | `CKV2_AWS_5` | `infra/terraform/main.tf:64` | HIGH | FP. Security group `app` dành cho tầng tính toán (ECS) không được mô hình hóa trong mẫu |
| 11 | Checkov | `CKV2_AWS_62` | `infra/terraform/main.tf:175` | HIGH | Chấp nhận được. Bucket log không cần thông báo sự kiện |
| 12 | Checkov | `CKV2_AWS_62` | `infra/terraform/main.tf:179` | HIGH | Chấp nhận được. Bucket ảnh chụp không cần thông báo sự kiện |
| 13 | Checkov | `CKV_AWS_144` | `infra/terraform/main.tf:175` | HIGH | Chấp nhận được. Sao chép sang region khác là quyết định về chi phí và độ sẵn sàng, không phải lỗ hổng |
| 14 | Checkov | `CKV_AWS_144` | `infra/terraform/main.tf:179` | HIGH | Chấp nhận được, như #13 |
| 15 | Checkov | `CKV_K8S_35` | `infra/k8s/deployment.yaml:3` | HIGH | Chấp nhận được. Ứng dụng đọc cấu hình từ biến môi trường (12-factor); secret được lấy từ Secret của K8s chứ không viết thẳng |

## Ghi chú cho báo cáo

- **Checkov không có mức độ** khi chạy không kèm API key của Prisma Cloud. Mọi check không đạt đều có level `error`, nên gate quy về HIGH. Đó là lý do một PR chỉ *thêm* hạ tầng mẫu (PR #3) đã bị gate truyền thống chặn bởi 10 FP.
- **Semgrep và Trivy cho 0 phát hiện** trên bản sạch. Kịch bản lỗ hổng nào khiến hai công cụ này báo thì gần như chắc chắn là TP.
- **Gitleaks báo trên file test.** Bảng trên quét toàn bộ cây (`gitleaks dir`). Trên CI, Gitleaks chỉ quét **các commit của PR** (`gitleaks git --log-opts base..head`). Vì vậy hai FP này chỉ xuất hiện khi commit của PR thêm hoặc sửa đúng những dòng đó. Gate không lọc kết quả Gitleaks theo file thay đổi, vì secret đã commit rồi bị đổi tên hoặc xóa vẫn nằm trong lịch sử.
- **Quét lại sau review cuối kế hoạch B** (cùng ngày) với cấu hình mới: zizmor quét từ gốc repo, Semgrep/Bandit/Gitleaks bỏ qua comment chặn cảnh báo, công cụ Python cài với `--exclude-newer`, bucket logs có thêm policy chỉ cho phép TLS. Kết quả **không đổi**: cùng 14 phát hiện ở cùng vị trí, cộng phát hiện CodeQL.
- Không có comment chặn cảnh báo nào (`# nosec`, `checkov:skip`, …) trong `app/` và `infra/`. Mọi FP trên đều được giữ nguyên để đo.
