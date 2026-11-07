# infra/

| Thư mục / file | Mục đích |
|---|---|
| `docker-compose.yml` | **Chạy thật**: demo trên máy và staging tạm thời trong CI (`main-ci.yml`) |
| `terraform/` | Hạ tầng AWS mẫu (VPC, RDS PostgreSQL, S3 lưu ảnh chụp, KMS). **Chỉ dùng làm đối tượng cho IaC Scan**, không `terraform apply` |
| `k8s/` | Manifest Kubernetes mẫu. **Chỉ dùng làm đối tượng cho IaC Scan** |

Terraform và K8s được viết theo thực hành bảo mật tốt, vì đây là bản sạch. Các check của Checkov còn báo trên bản sạch được ghi lại ở [`docs/baseline-scan.md`](../docs/baseline-scan.md), làm dữ liệu báo nhầm (FP) cho thực nghiệm. Không dùng `checkov:skip` để ẩn chúng.

Các kịch bản lỗ hổng IaC trong benchmark (ví dụ S10: container chạy bằng root, bucket để public) sẽ là patch thay đổi các file này.
