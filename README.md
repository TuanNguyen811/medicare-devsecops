# MediCare DevSecOps

Đồ án tốt nghiệp ngành An toàn thông tin: **Xây dựng quy trình DevSecOps tích hợp AI Security Agent hỗ trợ phát hiện, thẩm định và khắc phục lỗ hổng bảo mật.**

- `app/`: MediCare HMS, hệ thống quản lý bệnh viện mẫu (FastAPI), là ứng dụng mục tiêu
- `agent/`: AI Security Agent (Python, Function Calling, DeepSeek API)
- `.github/workflows/`: pipeline CI/CD tích hợp SAST, SCA, Secret Scan, IaC Scan
- `benchmark/`: bộ thực nghiệm so sánh DevSecOps truyền thống và DevSecOps tích hợp AI Agent
- `docs/`: thiết kế và tài liệu

Thiết kế chi tiết: [docs/superpowers/specs/2026-11-07-devsecops-ai-agent-design.md](docs/superpowers/specs/2026-11-07-devsecops-ai-agent-design.md)

> ⚠️ Repo này chứa các kịch bản lỗ hổng **được cài có chủ đích** phục vụ nghiên cứu. Không triển khai các nhánh kịch bản lên môi trường public. Toàn bộ dữ liệu bệnh nhân là dữ liệu giả.

## Cho lập trình viên

- Chạy ứng dụng và test: xem [`app/README.md`](app/README.md).
- Bật kiểm tra trước khi commit (chặn secret bằng Gitleaks, lint bằng Ruff):

  ```bash
  uv tool install pre-commit
  pre-commit install
  ```

- Pipeline bảo mật trên GitHub Actions: xem [`docs/pipeline.md`](docs/pipeline.md).
