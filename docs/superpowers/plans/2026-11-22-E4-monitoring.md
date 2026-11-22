# Giai đoạn 4: Giám sát Implementation Plan

> **For agentic workers:** Native (Claude tự làm, review toàn nhánh ở cuối). Steps use checkbox (`- [ ]`) syntax.

**Goal:**
- App xuất metrics Prometheus ở cổng riêng.
- Prometheus, Alertmanager, Grafana chạy trong cụm của Docker Desktop, được `pull-deploy.sh` apply.
- 6 luật cảnh báo, demo được bằng `simulate-traffic.py`.

**Architecture:**
- **App:** module `medicare/common/metrics.py`.
  - Middleware ASGI ngoài cùng đếm request theo mẫu route.
  - Đếm đăng nhập trong `authenticate`, truy cập bệnh án trong `log_access`, từ chối quyền ở các chỗ `can_*` trả về không cho phép.
  - `prometheus_client.start_http_server` chạy trong lifespan khi có `METRICS_PORT`.
- **Cụm:**
  - `deploy/local/metrics.yaml`: Service headless và NetworkPolicy cổng 9000.
  - `deploy/monitoring/`: kustomize, configMapGenerator, NetworkPolicy default-deny.

**Tech Stack:** prometheus-client 0.26, Prometheus v3.16.0, Alertmanager v0.35.0, Grafana 13.3.1 (ghim digest).

**Spec:** `docs/superpowers/specs/2026-11-21-ops-dast-engine-design.md` mục 7 (các quyết định khi làm ở 7.4).

## Global Constraints

- **Nhãn metrics không có PII (R-10):**
  - `route` là mẫu đường dẫn, không phải URL thật; route không khớp thì ghi `unmatched`;
  - `user_id` là số nội bộ.
- Cổng 9000 không đi qua Service của app hay port-forward. Chỉ Prometheus vào được cổng này.
- Image ghim digest; Checkov trên `deploy/` sạch; mọi truy cập qua `kubectl port-forward` ở `127.0.0.1`.
- Mật khẩu Grafana sinh tại chỗ, nằm trong secret của cụm, đọc từ file. Chỉ in một lần.
- Cảnh báo không gửi ra ngoài: receiver duy nhất là `null`.
- `simulate-traffic.py` chỉ nhắm `127.0.0.1` hoặc `localhost`.
- Không sửa `infra/k8s/`.

## Tasks

### Task 1: Metrics trong app
- [x] `metrics.py` (counter, histogram, middleware, `start_metrics_server`). `Settings.metrics_port` (mặc định tắt) và `metrics_host` (mặc định `127.0.0.1`).
- [x] Gắn vào `authenticate` (success, failure, locked, lockout), vào nhánh input quá dài ở router login, vào `require_roles`, `log_access`, và các chỗ từ chối trong service (tách nhánh không tồn tại khỏi nhánh bị từ chối).
- [x] `tests/test_metrics.py`:
  - đếm đăng nhập và khóa tài khoản;
  - truy cập bệnh án theo người;
  - từ chối chỉ đếm đối tượng có thật;
  - nhãn route là mẫu đường dẫn, không chứa dữ liệu thật;
  - server tắt mặc định và không nằm trên cổng app;
  - server bật ở cổng riêng;
  - các chuỗi được xuất từ lúc import.

### Task 2: Stack giám sát và deploy
- [x] `deploy/local`: patch thêm env và cổng `metrics`, `metrics.yaml`.
- [x] `deploy/monitoring`: Prometheus (`dns_sd` tới `medicare-metrics`), 6 luật trong `rules.yml`, Alertmanager (receiver null, tắt cluster), Grafana (datasource và dashboard được provision, tắt ẩn danh, tắt gọi ra ngoài), NetworkPolicy.
- [x] `pull-deploy.sh` bước 7: namespace, secret `grafana-admin`, `apply -k`, rollout, chờ `sum(up{job="medicare"}) == 1`.
- [x] `promtool check rules`, `amtool check-config`, Checkov `deploy/`: sạch.

### Task 3: `simulate-traffic.py`
- [x] `normal`, `brute-force`, `idor-probe`, `bulk-read`. Kiểm tra host. Lấy mật khẩu demo từ env hoặc từ secret trong cụm.

### Task 4: Kiểm chứng trên cụm (image nhánh, bản sao thử dùng danh tính nhánh)
- [x] Deploy kèm giám sát đạt; Prometheus lấy được metrics; pod ở namespace `default` không vào được cổng 9000.
- [x] Grafana: dashboard "MediCare Security"; datasource OK; ẩn danh nhận 401.
- [x] `normal` 90 giây: không có cảnh báo. `brute-force`, `idor-probe`, `bulk-read`: bật lần lượt `BruteForceSuspected`, `AccountLockout`, `AuthzDeniedSpike`, `RecordAccessSpike`. Hạ app về 0 replica thì bật `AppDown`.
- [x] Phát hiện khi thử: 30 lần sai chỉ đếm được 21 (sát ngưỡng). Đã sửa bằng cách khởi tạo sẵn các nhãn, có test.
- [x] Áp lại policy thật (danh tính `main`) sau khi thử.

### Task 5: Review toàn nhánh, PR, sau merge
- [x] Review (Opus): 0 Critical, 1 Important, 5 Minor; đã sửa hết.
  - **I1:** `RecordAccessSpike` bỏ sót đợt đọc hàng loạt từ một chuỗi mới (chuỗi theo từng người dùng không tạo sẵn được). Đã sửa: xét thêm giá trị thô của chuỗi dưới 5 phút tuổi. Có `rules-test.yml` để kiểm bằng promtool; với luật cũ, test này thất bại.
  - **M1, M2:** hủy lịch bị từ chối vì trạng thái, và đặt lịch cho id bệnh nhân không tồn tại, không còn tính là từ chối quyền.
  - **M3:** method lạ ghi thành `OTHER`.
  - **M4:** `HighErrorRate` và dashboard bỏ `/health` khỏi phép tính, và không chia cho 0.
  - **M5:** `simulate-traffic.py` không đi qua proxy hệ thống.
  - Test server metrics dùng cổng trống bất kỳ.
- [ ] PR, theo dõi CI.
- [ ] Sau merge: `pull-deploy.sh` thật, rồi chạy lại `brute-force` để xác nhận số đếm đủ.
