# deploy/

Deploy MediCare HMS về cụm Kubernetes của Docker Desktop trên máy, theo kiểu **kéo về** (spec bổ sung mục 6). CI không bao giờ chạm vào máy này: CI chỉ build, ký và đẩy image lên GHCR, còn máy tự kéo về sau khi kiểm tra chữ ký.

```
main-ci (GitHub)                                  máy này
  build → Trivy → SBOM → push GHCR                  deploy/pull-deploy.sh
  → cosign sign + attest (keyless, OIDC)   ──►        cosign verify + verify-attestation
                                                      → Kyverno (admission) kiểm tra lại
                                                      → apply deploy/local → rollout
                                                      → smoke test (lỗi: rollback)
                                                      → ZAP quét bản vừa deploy
```

## Yêu cầu

- Docker Desktop có bật Kubernetes, context `docker-desktop`. Tài nguyên khuyến nghị: 6 CPU, 8 GB RAM.
- Git Bash (Windows) hoặc bash (Linux), có `kubectl`, `docker`, `curl`, `openssl`, `python`.
- Image `ghcr.io/tuannguyen811/medicare-hms` là public, nên không cần đăng nhập GHCR.

## Lệnh

```bash
bash deploy/pull-deploy.sh                 # bản main mới nhất (:latest → digest)
bash deploy/pull-deploy.sh --digest sha256:<...>
bash deploy/pull-deploy.sh --skip-dast     # bỏ bước ZAP (khoảng 25 phút)
bash deploy/demo-unsigned.sh               # demo: cụm từ chối image không do main-ci ký
```

**Lần chạy đầu:**
- Cài Kyverno 1.20.0. Manifest phát hành được kiểm tra sha256 trong `security/tool-versions.env`.
- Áp policy `kyverno/image-policy.yaml`.
- Tạo secret `medicare-db` và `medicare-env` (chỉ nằm trong cụm, không ghi ra repo).
- Seed dữ liệu demo. **Mật khẩu demo chỉ in ra một lần.** Đọc lại bằng:
  ```bash
  kubectl -n medicare get secret medicare-env -o jsonpath='{.data.DEMO_PASSWORD}' | base64 -d
  ```

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
2. **Kyverno `ImageValidatingPolicy`** ở admission, áp cho mọi pod trong namespace `medicare`:
   - image MediCare phải tham chiếu theo digest;
   - phải có chữ ký đúng danh tính;
   - phải có attestation SBOM CycloneDX.

   Lớp này vẫn chặn được kể cả khi ai đó `kubectl apply` bằng tay.

`main-ci` ký ở mọi lần chạy, kể cả chạy thủ công từ nhánh khác. Chứng chỉ ghi rõ workflow và ref, nên image do nhánh khác ký vẫn bị từ chối.

Script không có cờ nào để bỏ qua kiểm tra chữ ký.

## Thư mục

| File | Việc |
|---|---|
| `local/` | Kustomize overlay dựa trên `infra/k8s`: 1 bản sao app, PostgreSQL (StatefulSet, PVC `local-path`), NetworkPolicy cho DNS và app → db. Không sửa `infra/k8s`, vì đó là đối tượng quét IaC của benchmark |
| `kyverno/image-policy.yaml` | Policy kiểm tra chữ ký ở admission |
| `install-tools.sh` | Tải cosign ghim sha256 vào `.tools/` |
| `pull-deploy.sh` | Deploy kiểu kéo về như sơ đồ trên |
| `demo-unsigned.sh` | Dry-run phía server với một image không do `main` ký, để thấy Kyverno từ chối |

**Các file sinh ra khi chạy (không commit):**
- `.tools/`: cosign, manifest Kyverno;
- `reports/<thời điểm>/`: báo cáo ZAP sau deploy;
- `.history`: lịch sử các lần deploy.

## Ghi chú

- Image Kyverno được kéo từ `ghcr.io/kyverno/*` thay cho `reg.kyverno.io/kyverno/*`. Hai nơi có cùng digest, nhưng kéo từ `reg.kyverno.io` bên trong node Docker Desktop hay lỗi (`short read: unexpected EOF`).
- Webhook của policy đặt timeout 30 giây. Mặc định 10 giây không đủ để Kyverno lấy chữ ký từ GHCR trong cụm cục bộ.
- Mọi truy cập đều qua `kubectl port-forward` ở `127.0.0.1`. Không mở ra mạng ngoài.
