# deploy/

Deploy MediCare HMS về cụm Kubernetes của Docker Desktop trên máy, theo kiểu **kéo về** (spec bổ sung mục 6). CI không bao giờ chạm vào máy này: CI chỉ build, ký và đẩy image lên GHCR, còn máy tự kéo về sau khi kiểm tra chữ ký.

```
main-ci (GitHub)                                  máy này
  build → Trivy → SBOM → push GHCR                  deploy/pull-deploy.sh
  → cosign sign + attest (keyless, OIDC)   ──►        cosign verify + verify-attestation
                                                      → Kyverno (admission) kiểm tra lại
                                                      → apply deploy/local → rollout
                                                      → smoke test (lỗi: rollback)
                                                      → (--dast) ZAP quét bản vừa deploy
```

## Yêu cầu

- Docker Desktop có bật Kubernetes, context `docker-desktop`. Tài nguyên khuyến nghị: 6 CPU, 8 GB RAM.
- Git Bash (Windows) hoặc bash (Linux), có `kubectl`, `docker`, `curl`, `openssl`, `python`.
- Image `ghcr.io/tuannguyen811/medicare-hms` là public, nên không cần đăng nhập GHCR.

## Lệnh

```bash
bash deploy/pull-deploy.sh                 # bản main mới nhất (:latest → digest), 1-2 phút
bash deploy/pull-deploy.sh --digest sha256:<...>
bash deploy/pull-deploy.sh --dast          # thêm ZAP quét bản vừa deploy, 5 vai trò (~25 phút)
bash deploy/demo-unsigned.sh               # demo: cụm từ chối image không do main-ci ký
```

**Lần chạy đầu:**
- Cài Kyverno 1.20.0. Manifest phát hành được kiểm tra sha256 trong `security/tool-versions.env`.
- Áp policy `kyverno/image-policy.yaml`.
- Tạo secret `medicare-db` và `medicare-env` (chỉ nằm trong cụm, không ghi ra repo). Secret nào thiếu thì tạo secret đó.
- **Mật khẩu demo chỉ in ra một lần.** Đọc lại bằng:
  ```bash
  kubectl -n medicare get secret medicare-env -o jsonpath='{.data.DEMO_PASSWORD}' | base64 -d
  ```

Mỗi lần deploy đều chạy `python -m medicare.seed` trong pod mới. Nếu dữ liệu đã có thì lệnh này không làm gì, nên một lần chạy đầu bị lỗi giữa chừng cũng không để lại database rỗng. Seed bằng `kubectl exec` thay cho Job: không phải thay digest lần thứ hai, và không đưa secret vào biến môi trường của một pod khác.

Smoke test, seed và việc xuất route chỉ nhắm vào pod mới (đúng digest vừa kiểm tra, không phải pod đang tắt). Script dùng cổng riêng `127.0.0.1:18001`. Nếu cổng bị chiếm thì script dừng, chứ không lặng lẽ kiểm tra nhầm bản khác.

**Truy cập app:**
```bash
kubectl -n medicare port-forward --address 127.0.0.1 svc/medicare-app 18000:80
# rồi mở http://127.0.0.1:18000
```

## Hai lớp kiểm tra chữ ký

Danh tính hợp lệ duy nhất:
- identity `https://github.com/TuanNguyen811/medicare-devsecops/.github/workflows/main-ci.yml@refs/heads/main`;
- issuer `https://token.actions.githubusercontent.com`.

1. **`cosign verify` và `cosign verify-attestation --type cyclonedx`** trong `pull-deploy.sh`, chạy trước khi đụng vào cụm. Sai thì dừng.
2. **Kyverno `ImageValidatingPolicy`** ở admission, áp cho mọi pod trong namespace `medicare` (cả `containers`, `initContainers` lẫn container thêm bằng `kubectl debug`):
   - **danh sách cho phép:** chỉ chấp nhận image MediCare theo digest (`ghcr.io/tuannguyen811/medicare-hms@sha256:...`) hoặc đúng image PostgreSQL đã ghim. Mọi image khác bị từ chối, kể cả khi viết registry kiểu khác như `ghcr.io:443/...`;
   - image MediCare phải có chữ ký đúng danh tính;
   - image MediCare phải có attestation SBOM CycloneDX của cùng danh tính.

   Lớp này vẫn chặn được kể cả khi ai đó `kubectl apply` bằng tay.

   Policy đặt `failurePolicy: Fail`. Khi Kyverno không quyết định được (Kyverno ngừng chạy, hoặc không có mạng tới Rekor/GHCR), mọi pod trong `medicare`, kể cả PostgreSQL, sẽ không tạo lại được. Đây là chặn an toàn có chủ đích. Trước buổi demo, cần kiểm tra mạng.

`main-ci` ký ở mọi lần chạy, kể cả chạy thủ công từ nhánh khác. Chứng chỉ ghi rõ workflow và ref, nên image do nhánh khác ký vẫn bị từ chối.

Script không có cờ nào để bỏ qua kiểm tra chữ ký.

## Thư mục

| File | Việc |
|---|---|
| `local/` | Kustomize overlay dựa trên `infra/k8s`: 1 bản sao app, PostgreSQL (StatefulSet, uid 10070, PVC dùng StorageClass mặc định `standard`, tức `rancher.io/local-path`), NetworkPolicy cho DNS (chỉ tới `kube-dns`) và app → db. Không sửa `infra/k8s`, vì đó là đối tượng quét IaC của benchmark |
| `kyverno/image-policy.yaml` | Policy kiểm tra chữ ký ở admission |
| `install-tools.sh` | Tải cosign ghim sha256 vào `.tools/` |
| `pull-deploy.sh` | Deploy kiểu kéo về như sơ đồ trên |
| `demo-unsigned.sh` | Dry-run phía server với một image không do `main` ký, để thấy Kyverno từ chối |

**Các file sinh ra khi chạy (không commit):**
- `.tools/`: cosign, manifest Kyverno;
- `reports/<thời điểm>/`: báo cáo ZAP sau deploy;
- `.history`: lịch sử các lần deploy.

## Ghi chú

- Image Kyverno được kéo từ `ghcr.io/kyverno/*` thay cho `reg.kyverno.io/kyverno/*`, vì kéo từ `reg.kyverno.io` bên trong node Docker Desktop hay lỗi (`short read: unexpected EOF`). Manifest tham chiếu theo tag. Hai registry đều do dự án Kyverno phát hành, và đã đối chiếu cùng digest vào ngày ghim (2026-11-22).
- Webhook của policy đặt timeout 30 giây. Mặc định 10 giây không đủ để Kyverno lấy chữ ký từ GHCR trong cụm cục bộ.
- Mọi truy cập đều qua `kubectl port-forward` ở `127.0.0.1`. Không mở ra mạng ngoài.
- **NetworkPolicy được thực thi trên cụm này** (kiểm tra 2026-11-22). Pod nhãn `app=medicare` chạy `pg_isready` tới `medicare-db:5432` nhận được "accepting connections". Pod nhãn khác thì "no response".
- `kubectl port-forward` tự thoát khi gặp kết nối hỏng, mà ZAP quét chủ động tạo ra kết nối hỏng trong vài phút. Vì vậy script chạy port-forward trong vòng lặp tự khởi động lại suốt bước smoke test và DAST.
- Trạng thái `READY` của policy hiển thị `false`, vì bộ phận báo cáo của Kyverno thiếu quyền đọc `pods/ephemeralcontainers`. Việc chặn ở admission vẫn hoạt động. Script chờ điều kiện `WebhookConfigured=True`.
