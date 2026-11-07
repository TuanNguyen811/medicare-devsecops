# MediCare HMS

Hệ thống quản lý bệnh viện mẫu, là **ứng dụng mục tiêu** của quy trình DevSecOps trong đồ án. Nhánh `main` là bản sạch, viết theo các quy tắc bảo mật ở [docs/security-requirements.md](../docs/security-requirements.md). Toàn bộ dữ liệu là dữ liệu giả.

## Chạy bằng Docker (demo)

Yêu cầu: Docker Desktop. Mọi lệnh chạy từ thư mục gốc của repo.

1. Tạo file cấu hình:

   ```bash
   cp app/.env.example app/.env
   ```

   Sửa `app/.env`:
   - `SECRET_KEY`: sinh bằng `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Ứng dụng **không khởi động** nếu khóa còn chứa `change-me`.
   - `POSTGRES_PASSWORD`: đặt mật khẩu mới, và sửa phần mật khẩu trong `DATABASE_URL` cho khớp.
   - `DEMO_PASSWORD`: mật khẩu chung cho các tài khoản demo, tối thiểu 10 ký tự.

2. Khởi động (migration chạy tự động):

   ```bash
   docker compose -f infra/docker-compose.yml up -d --build
   curl -fsS http://127.0.0.1:8000/health
   ```

3. Nạp dữ liệu mẫu (chỉ chạy được khi `ENV=development`):

   ```bash
   docker compose -f infra/docker-compose.yml exec app python -m medicare.seed
   ```

4. Mở http://127.0.0.1:8000 và đăng nhập bằng một tài khoản demo, mật khẩu là `DEMO_PASSWORD`:

   | Tài khoản | Vai trò |
   |---|---|
   | `admin` | Quản trị viên |
   | `letan1` | Lễ tân |
   | `bacsi1`, `bacsi2` (Nội), `bacsi3` (Ngoại), `bacsi4` (Nhi) | Bác sĩ |
   | `yta1` (Nội), `yta2` (Ngoại), `yta3` (Nhi) | Điều dưỡng |
   | `benhnhan1` … `benhnhan5` | Bệnh nhân |

Ứng dụng chỉ lắng nghe trên `127.0.0.1`. Không mở ra mạng, và **không bao giờ** triển khai các nhánh kịch bản lỗ hổng lên môi trường public.

Dừng: `docker compose -f infra/docker-compose.yml down`. Thêm `-v` để xóa luôn dữ liệu.

## Phát triển

Yêu cầu: [uv](https://docs.astral.sh/uv/) và Docker (bộ test khởi tạo PostgreSQL thật bằng Testcontainers).

```bash
cd app
uv sync
uv run pytest -q
uv run ruff check
```

Cấu trúc mã nguồn: `medicare/<module>/{router,service,models,schemas}.py`. Phân quyền theo đối tượng chỉ đi qua các hàm `can_*` trong `medicare/policy.py`.
