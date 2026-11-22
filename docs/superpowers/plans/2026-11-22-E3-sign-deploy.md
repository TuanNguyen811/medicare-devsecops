# Giai đoạn 3: Ký image và deploy về Kubernetes trên máy Implementation Plan

> **For agentic workers:** Native (Claude tự làm, review toàn nhánh ở cuối). Steps use checkbox (`- [ ]`) syntax.

**Goal:**
- `main-ci` ký image keyless bằng cosign và gắn SBOM CycloneDX attestation.
- `deploy/pull-deploy.sh` kéo bản `main` mới nhất về cụm Kubernetes của Docker Desktop: kiểm tra chữ ký, apply, smoke test, lỗi thì rollback, rồi ZAP quét bản vừa deploy.
- Kyverno trong cụm từ chối mọi image MediCare không được `main-ci` của repo ký.

**Architecture:**
- **CI (`main-ci.yml`, job `image`):** push image → lấy digest → `cosign sign` + `cosign attest --type cyclonedx`, keyless qua OIDC của GitHub. Mặc định của cosign v3 là định dạng bundle lưu qua OCI referrer.
- **Trên máy:**
  - `deploy/install-tools.sh`: tải cosign ghim sha256 cho Windows hoặc Linux.
  - `deploy/pull-deploy.sh`: lần đầu cài Kyverno (manifest ghim sha256) và policy, tạo secret. Sau đó kiểm tra chữ ký bằng cosign, render overlay `deploy/local` với digest, apply, rollout, smoke test qua port-forward `127.0.0.1`, lỗi thì `rollout undo`, rồi chạy `run-dast.sh`.
- **Hai lớp kiểm tra chữ ký:** cosign trên máy (trước khi đụng vào cụm) và Kyverno `ImageValidatingPolicy` (admission, kể cả khi ai đó `kubectl apply` bằng tay).

**Tech Stack:** cosign v3.1.4, Kyverno v1.20.0 (`ImageValidatingPolicy`, `policies.kyverno.io/v1`, vì bản 1.20 chặn tạo policy kiểu cũ), kustomize (`kubectl -k`), Docker Desktop Kubernetes (kind, 1 node).

**Spec:** `docs/superpowers/specs/2026-11-21-ops-dast-engine-design.md` mục 6.

## Global Constraints

- **Danh tính ký hợp lệ duy nhất:**
  - identity `https://github.com/TuanNguyen811/medicare-devsecops/.github/workflows/main-ci.yml@refs/heads/main`;
  - issuer `https://token.actions.githubusercontent.com`.

  Dùng ở cả `pull-deploy.sh` lẫn policy Kyverno.
- **Ký ở mọi lần chạy `main-ci`** (kể cả `workflow_dispatch` từ nhánh khác). Danh tính ghi rõ nhánh, nên image nhánh khác ký vẫn bị từ chối. *(Ruling: spec 6.1 nói chỉ ký trên `main`; ký mọi lần chạy vẫn an toàn vì danh tính bị ghim, lại thử được trước khi merge, và có thêm tình huống demo "ký sai danh tính".)*
- Không sửa `infra/k8s/`. Overlay `deploy/local` lấy nó làm nền.
- App, PostgreSQL và (giai đoạn 4) Grafana chỉ truy cập qua `kubectl port-forward` ở `127.0.0.1`.
- Secret sinh tại chỗ, lưu trong cụm, không ghi vào repo. `DEMO_PASSWORD` chỉ in một lần lúc tạo.
- Manifest mới phải sạch Checkov (CI quét toàn repo; finding HIGH trên file đổi sẽ chặn PR):
  - image theo digest;
  - `securityContext` chặt;
  - có `resources` và probe.
- Phiên bản ghim trong `security/tool-versions.env`: `COSIGN_VERSION`, `COSIGN_SHA256` (linux-amd64), `COSIGN_WINDOWS_SHA256`, `KYVERNO_VERSION`, `KYVERNO_INSTALL_SHA256`.
- Không thêm cờ bỏ qua kiểm tra chữ ký vào script deploy.


## Thay đổi so với kế hoạch khi làm (ghi lại sau review)

- **Seed:** không dùng Job `seed-job.yaml`. Mỗi lần deploy chạy `kubectl exec <pod mới> -- python -m medicare.seed`; lệnh không làm gì nếu dữ liệu đã có. Lý do:
  - Checkov CKV_K8S_35 cấm Job đọc secret qua biến môi trường;
  - không phải thay digest lần thứ hai;
  - một lần chạy đầu bị lỗi giữa chừng không để lại database rỗng.
- **PostgreSQL chạy uid 10070** thay vì 70, để qua Checkov CKV_K8S_40 (uid cao). Image chính thức hỗ trợ uid tùy ý. `PGDATA` đặt ở thư mục con.
- **Digest được thay lúc render** (`kubectl kustomize | sed`), không dùng `set image` sau khi apply. Kyverno chặn digest toàn số 0 ngay ở bước apply.
- **Policy Kyverno theo kiểu danh sách cho phép** cho cả namespace: xét `containers`, `initContainers`, `ephemeralContainers` và subresource `pods/ephemeralcontainers`; đặt `failurePolicy: Fail`.
- **Image Kyverno kéo từ `ghcr.io/kyverno`** thay cho `reg.kyverno.io`, vì kéo từ `reg.kyverno.io` trong node Docker Desktop bị lỗi `short read`.
- **Ký trên mọi lần chạy `main-ci`.** `:latest` chỉ được đẩy sau khi ký và attest thành công.

## Tasks

### Task 1: Ký trong `main-ci`
- [ ] `tool-versions.env` thêm cosign và Kyverno. `security/install-tools.sh` cài thêm cosign (Linux, kiểm sha256).
- [ ] Job `image`:
  - thêm quyền `id-token: write`;
  - step push lấy digest (`docker inspect --format '{{index .RepoDigests 0}}'`), rồi `cosign sign --yes <image>@<digest>` và `cosign attest --yes --type cyclonedx --predicate sbom.cdx.json <image>@<digest>`, sau đó logout;
  - ghi digest vào step summary.
- [ ] zizmor sạch. Commit `ci: ký image và gắn SBOM attestation bằng cosign (keyless)`.

### Task 2: Overlay `deploy/local`
- [ ] `kustomization.yaml`: resources `../../infra/k8s` + `postgres.yaml` + `networkpolicy.yaml` + `seed-job.yaml`; patch `replicas: 1`; patch app thêm env `ENV=development` (chạy HTTP qua port-forward) nếu cần.
- [ ] `postgres.yaml`: StatefulSet + Service + PVC (`local-path`), image `postgres:16-alpine` ghim digest, chạy uid 70, root filesystem chỉ đọc kèm `emptyDir` cho `/var/run/postgresql` và `/tmp`, đọc secret `medicare-db`.
- [ ] `networkpolicy.yaml`: DNS ra `kube-system` cổng 53; app → db cổng 5432; db nhận từ app; app ra cổng 5432.
- [ ] `seed-job.yaml`: Job `medicare-seed` chạy `python -m medicare.seed` bằng image app (digest do script đặt), đọc `medicare-env`.
- [ ] `kubectl kustomize deploy/local` render được. Checkov trên `deploy/` không có finding HIGH nào mới. Commit.

### Task 3: Kyverno policy
- [ ] `deploy/kyverno/image-policy.yaml`: `ImageValidatingPolicy` cho pod trong namespace `medicare`, khớp `ghcr.io/tuannguyen811/medicare-hms*`, yêu cầu digest, chữ ký keyless đúng danh tính, và attestation CycloneDX (`https://cyclonedx.org/bom`).
- [ ] Commit.

### Task 4: Script trên máy
- [ ] `deploy/install-tools.sh`: tải cosign đúng hệ điều hành vào `deploy/.tools/`, kiểm sha256.
- [ ] `deploy/pull-deploy.sh [--digest sha256:…] [--skip-dast]`:
  1. kiểm tra context `docker-desktop`;
  2. phân giải digest của `:latest`;
  3. `cosign verify` + `verify-attestation --type cyclonedx` theo danh tính ở trên;
  4. lần đầu: cài Kyverno (kiểm sha256 manifest) và policy, tạo namespace, secret `medicare-db` và `medicare-env`;
  5. render overlay với digest → `kubectl apply`;
  6. `rollout status` (timeout 180 giây) → seed job (lần đầu) → port-forward `127.0.0.1:18000` → smoke test;
  7. lỗi → `rollout undo`, thoát 1;
  8. thành công → export routes qua `kubectl exec`, rồi `run-dast.sh --target http://host.docker.internal:18000 --network bridge`, báo cáo ở `deploy/reports/<thời điểm>/`;
  9. ghi `deploy/.history`.
- [ ] `deploy/demo-unsigned.sh`: `kubectl run --dry-run=server` với một image MediCare không được `main` ký (theo digest) → in lỗi Kyverno.
- [ ] `deploy/README.md`. `.gitignore`: `deploy/.tools/`, `deploy/reports/`, `deploy/.history`.
- [ ] Commit.

### Task 5: Kiểm chứng
- [ ] Chạy `main-ci` thủ công trên nhánh (`gh workflow run main-ci.yml --ref feat/sign-deploy`) → image được ký bằng danh tính của nhánh.
- [ ] Trên máy:
  - `cosign verify` với danh tính nhánh phải đạt, với danh tính `main` phải bị từ chối;
  - policy Kyverno bản thử (danh tính nhánh) cho qua pod dry-run, bản thật (danh tính `main`) từ chối, image chưa ký bị từ chối;
  - overlay chạy được trên cụm (app, db, seed, smoke test), thử bằng một bản sao policy chỉ dùng cho lần thử.
- [ ] Ghi kết quả vào mô tả PR.

### Task 6: Review toàn nhánh (Opus), PR, sau merge chạy `pull-deploy.sh` thật
- [ ] Review, sửa, push, mở PR, theo dõi CI, xin label.
- [ ] Sau khi merge và `main-ci` ký bản `main`: chạy `deploy/pull-deploy.sh` từ đầu đến cuối, rồi `demo-unsigned.sh`. Sửa tiếp trong PR sau nếu cần.
