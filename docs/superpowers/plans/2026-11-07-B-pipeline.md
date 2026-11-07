# Kế hoạch B: Pipeline DevSecOps (GitHub Actions + công cụ quét + quality gate)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Xây pipeline DevSecOps "truyền thống" trên GitHub Actions cho repo `medicare-devsecops`:
- Mỗi PR chạy SAST (Semgrep, CodeQL, Bandit), SCA (Trivy), Secret Scan (Gitleaks), IaC Scan (Checkov + zizmor), xuất SARIF và quyết định chặn hay cho qua bằng quality gate.
- Mỗi lần merge vào `main` thì quét toàn bộ, quét Docker image, tạo SBOM, đẩy image lên GHCR và chạy staging tạm thời.
- Mỗi đêm quét lại thư viện phụ thuộc để bắt CVE mới.

**Architecture:**
- **Phiên bản công cụ:** khai báo ở đúng một file (`security/tool-versions.env`). Binary cài bằng script có kiểm tra sha256. Action của bên thứ ba được cố định bằng commit SHA.
- **Quality gate:** script Python thuần stdlib (`security/gate/gate.py`) đọc các file SARIF và (tùy chọn) `report.json` của Agent theo Hợp đồng 2. Gate chỉ xét phát hiện nằm trong **file mà PR thay đổi**. Có 2 chế độ `traditional` và `ai-assisted`; Agent lỗi thì gate quay về `traditional`.
- **Job Agent:** kế hoạch C mới cắm vào. Kế hoạch này để sẵn chỗ cho nó, và gate đã hiểu `report.json`.

**Tech Stack:** GitHub Actions, Semgrep, CodeQL (`github/codeql-action`), Bandit, Trivy, Gitleaks, Checkov, zizmor, actionlint, pre-commit, Terraform (chỉ để quét), Kubernetes manifest (chỉ để quét), Docker/GHCR. Python 3.12 + pytest cho gate.

**Spec:** `docs/superpowers/specs/2026-11-07-devsecops-ai-agent-design.md` (mục 1, 3). Hợp đồng giao tiếp: `docs/superpowers/plans/2026-11-07-00-roadmap.md` (Hợp đồng 2: SARIF, `report.json`, finding id, quy tắc gate).

## Global Constraints

- Phiên bản pin, lấy bản mới nhất ngày 2026-11-07:

  | Công cụ | Phiên bản |
  |---|---|
  | semgrep | 1.184.0 |
  | bandit | 1.9.4 |
  | trivy | 0.76.2 |
  | gitleaks | 8.30.1 |
  | checkov | 3.4.3 |
  | zizmor | 1.32.0 |
  | actionlint | 1.7.12 |

  Các Action: `actions/checkout` v7.0.1, `astral-sh/setup-uv` v10.3.3, `actions/upload-artifact` v7.0.2, `actions/download-artifact` v8.0.2, `github/codeql-action` tag v4 mới nhất (lấy SHA lúc triển khai).
- **Mọi `uses:` cố định bằng SHA đầy đủ 40 ký tự**, kèm comment ghi tag, ví dụ `uses: actions/checkout@<sha> # v7.0.1`. Lấy SHA bằng `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`; nếu là annotated tag thì phải giải tiếp sang commit.
- **Không dùng** `pull_request_target`. Không dùng Action quét của bên thứ ba (trivy-action, gitleaks-action): tải binary chính thức và kiểm tra sha256 đã ghi trong `security/tool-versions.env`.
- `permissions:` ở cấp workflow là `contents: read`. Job nào cần thêm quyền thì tự khai báo, ví dụ `security-events: write` để upload SARIF, `packages: write` để push GHCR.
- Không thêm comment chặn cảnh báo (`# nosec`, `# nosemgrep`, `# noqa: S…`, `checkov:skip`, `gitleaks:allow`) vào `app/` và `infra/`. Phát hiện trên bản sạch là dữ liệu FP của thực nghiệm. Thay vào đó, ghi kết quả vào `docs/baseline-scan.md`.
- Tên file SARIF đúng Hợp đồng 2: `sarif/{semgrep,codeql,bandit,trivy,gitleaks,checkov}.sarif`. zizmor ghi `sarif/zizmor.sarif` (gate đọc file này; Agent có thể bỏ qua).
- Mục tiêu thời gian pipeline PR: tổng ≤ 5 phút. Các job quét chạy song song.
- Secret của CI chỉ lấy từ `secrets.*` hoặc được sinh ngẫu nhiên ngay trong job (staging). Không bao giờ in secret ra log.
- Thư mục `security/gate/` chỉ dùng thư viện chuẩn. Test chạy bằng `uv run --with pytest pytest security/gate/tests -q` từ gốc repo.

## Review Focus

1. **SARIF thiếu trường hoặc hình dạng lạ** (không có `locations`, `ruleIndex` thay cho `ruleId`, URI tuyệt đối dạng `file:///github/workspace/...`): gate không được crash. Phát hiện không có vị trí tính là file `""` và luôn được xét (không lọc theo file thay đổi) → test ở Task 2 (`test_result_without_location_is_kept`).
2. **Không có file SARIF nào, hoặc file hỏng JSON:** thiếu file thì coi như công cụ đó không có phát hiện. **File hỏng thì gate chặn**, vì không đọc được kết quả quét thì không được cho qua → test ở Task 2 (`test_corrupt_sarif_blocks`).
3. **Chế độ `ai-assisted` khi Agent lỗi** (mã thoát 2, thiếu `report.json`, JSON hỏng): quay về `traditional` → test ở Task 2.
4. **PR từ fork** (không có secret, không có quyền ghi): các job cần quyền ghi phải tự bỏ qua, không làm đỏ cả pipeline → điều kiện `if:` ở Task 5, kiểm bằng actionlint/zizmor.
5. **Script injection trong workflow** (nhúng `${{ github.event.pull_request.title }}` vào `run:`): không được có. Kiểm bằng zizmor ở Task 5 và Task 6.

---

## Cấu trúc file

```
security/
├── tool-versions.env            # phiên bản + sha256 của mọi công cụ quét
├── install-tools.sh             # cài binary (trivy, gitleaks, actionlint) có kiểm tra sha256
├── semgrep/
│   ├── medicare.yml             # rule tùy chỉnh cho dự án
│   └── medicare.py, *.html      # file test của rule (chú thích ruleid/ok)
├── gitleaks.toml                # cấu hình gitleaks (dùng bộ rule mặc định)
├── checkov.yaml                 # framework, đầu ra
└── gate/
    ├── gate.py                  # quality gate
    └── tests/{test_gate.py, fixtures/}
infra/
├── docker-compose.yml           # (đã có)
├── terraform/{main.tf, variables.tf, outputs.tf, versions.tf}
└── k8s/{namespace.yaml, deployment.yaml, service.yaml, networkpolicy.yaml}
.github/workflows/{pr-security.yml, main-ci.yml, nightly-sca.yml}
.pre-commit-config.yaml
docs/pipeline.md                 # mô tả pipeline (phục vụ báo cáo)
docs/baseline-scan.md            # kết quả quét bản sạch v0.1-baseline (dữ liệu FP)
```

---

### Task 1: Phiên bản công cụ, script cài đặt, cấu hình công cụ quét, rule Semgrep tùy chỉnh

**Files:**
- Create: `security/tool-versions.env`, `security/install-tools.sh`, `security/semgrep/medicare.yml`, `security/semgrep/medicare.py`, `security/semgrep/medicare.html`, `security/gitleaks.toml`, `security/checkov.yaml`

**Interfaces:**
- Produces:
  - `security/tool-versions.env`: các dòng `KEY=value` cho `SEMGREP_VERSION`, `BANDIT_VERSION`, `CHECKOV_VERSION`, `ZIZMOR_VERSION`, `TRIVY_VERSION`, `TRIVY_SHA256` (bản `Linux-64bit.tar.gz`), `GITLEAKS_VERSION`, `GITLEAKS_SHA256` (bản `linux_x64.tar.gz`), `ACTIONLINT_VERSION`, `ACTIONLINT_SHA256` (bản `linux_amd64.tar.gz`). Workflow, benchmark và người dùng đều `source` file này.
  - `security/install-tools.sh <dest-dir>`: tải trivy, gitleaks, actionlint bản Linux x64, kiểm tra sha256 (`sha256sum -c`), giải nén vào `<dest-dir>`. Sai checksum thì thoát ≠ 0. Công cụ Python (semgrep, bandit[sarif], checkov, zizmor) cài trong workflow bằng `uv tool install <pkg>==<version>`.
  - Rule Semgrep tùy chỉnh, id có tiền tố `medicare.`:
    - `medicare.sqlalchemy-text-fstring`: `text(f"...")` hoặc `text("..." + x)`, CWE-89.
    - `medicare.jinja-safe-filter`: `|safe` hoặc `Markup(` trong template hay code, CWE-79.
    - `medicare.route-int-path-param`: route FastAPI có tham số `*_id: int` thay vì `ObjectId`, ánh xạ R-15. Kiểu `int` thường cho phép ID vượt phạm vi INTEGER của PostgreSQL và gây lỗi 500, đúng loại lỗi đã tìm thấy và sửa ở mảng A.

- [ ] **Step 1: Lấy sha256** của từng file release, ví dụ `gh release download v0.76.2 -R aquasecurity/trivy -p 'trivy_0.76.2_checksums.txt' -O -`, rồi lọc đúng dòng `Linux-64bit.tar.gz`. Làm tương tự với gitleaks và actionlint. Ghi vào `tool-versions.env`.
- [ ] **Step 2: Viết file test cho rule trước** (`medicare.py`, `medicare.html`). Mỗi trường hợp có chú thích `# ruleid: <id>` hoặc `# ok: <id>`; trong HTML dùng `<!-- ruleid: ... -->`. Tối thiểu 2 trường hợp `ruleid` và 2 trường hợp `ok` cho mỗi rule. Ví dụ trường hợp `ok`: `text("... :q")` có bind parameter; `patient_id: ObjectId`.
- [ ] **Step 3: Chạy** `docker run --rm -v "$PWD/security/semgrep:/src" semgrep/semgrep:1.184.0 semgrep --test /src`. Kỳ vọng: FAIL, vì chưa có rule.
- [ ] **Step 4: Viết** `medicare.yml`, mỗi rule có `metadata: {cwe, owasp, confidence}`. Viết `gitleaks.toml` (`[extend] useDefault = true`, không có allowlist) và `checkov.yaml` (`framework: [terraform, kubernetes, dockerfile, secrets]`, `compact: true`).
- [ ] **Step 5: Chạy lại** lệnh ở Step 3. Kỳ vọng: mọi test của rule PASS.
- [ ] **Step 6: Chạy** `bash security/install-tools.sh /tmp/tools` (trong WSL hoặc trong một container `ubuntu`). Kỳ vọng: 3 binary chạy được `--version`. Sửa sai 1 ký tự trong sha256 thì script phải thoát với mã ≠ 0.
- [ ] **Step 7: Commit** `ci(security): pin phiên bản công cụ quét, script cài đặt, rule Semgrep tùy chỉnh`

---

### Task 2: Quality gate (`security/gate/gate.py`)

**Files:**
- Create: `security/gate/gate.py`, `security/gate/tests/test_gate.py`, `security/gate/tests/fixtures/*.sarif`, `security/gate/tests/fixtures/report_*.json`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) Finding(tool: str, rule_id: str, severity: str, file: str, line: int)`. `severity` ∈ `LOW, MEDIUM, HIGH, CRITICAL`. Property `id` trả chuỗi `f"{tool}:{rule_id}:{file}:{line}"` (Hợp đồng 2).
  - `normalize_path(uri: str, workspace: str | None) -> str`: bỏ `file://`, bỏ tiền tố `workspace` và `/github/workspace/`, bỏ `./`, đổi `\` thành `/`.
  - `severity_of(result: dict, rule: dict | None, tool: str) -> str`, theo thứ tự ưu tiên:
    1. `tool == "gitleaks"` → `HIGH`.
    2. `result.properties["security-severity"]`, nếu thiếu thì lấy của `rule.properties`: số ≥ 9.0 → `CRITICAL`, ≥ 7.0 → `HIGH`, ≥ 4.0 → `MEDIUM`, còn lại `LOW`.
    3. `result.level`, nếu thiếu thì `rule.defaultConfiguration.level`: `error` → `HIGH`, `warning` → `MEDIUM`, `note`/`none`/không có → `LOW`.
  - `load_sarif(path: Path, tool: str, workspace: str | None) -> list[Finding]`: lấy rule theo `ruleId`, nếu không có thì theo `ruleIndex` trong `runs[].tool.driver.rules`. Kết quả không có `locations` thì `file=""`, `line=0`. Ném `SarifError` nếu JSON hỏng hoặc thiếu `runs`.
  - `load_all(sarif_dir: Path, workspace) -> tuple[list[Finding], list[str]]`: đọc mọi file `*.sarif` trong thư mục, tên tool lấy từ tên file. Trả về `(findings, errors)`, với `errors` là danh sách file đọc lỗi.
  - `filter_changed(findings, changed: set[str]) -> list[Finding]`: giữ phát hiện có `file in changed` hoặc `file == ""`.
  - `decide(findings, *, mode, report, labels, agent_exit, errors) -> Decision`. `Decision(block: bool, mode_used: str, blocking: list[str], notes: list[str])`. Quy tắc nguyên văn từ Hợp đồng 2:
    - `errors` khác rỗng → `block=True`.
    - `traditional`: chặn khi có phát hiện `HIGH` hoặc `CRITICAL`.
    - `ai-assisted`: nếu `agent_exit != 0` hoặc `report is None` → dùng logic `traditional` với `mode_used="traditional (fallback)"`. Ngược lại, dựng map `id → kết luận` từ `report["findings"][*]["finding_ids"]`; với mỗi phát hiện HIGH/CRITICAL:
      - không có trong map → chặn;
      - `TP` hoặc `NEEDS_REVIEW` → chặn;
      - `FP` và mức `CRITICAL` mà không có label `security-reviewed` → chặn;
      - `FP` còn lại → không chặn, ghi vào `notes`.
      Ngoài ra chặn với mọi kết luận có `source == "agent"`, `verdict == "TP"`, `severity` ∈ HIGH/CRITICAL và `confidence >= 0.7`.
  - `render_summary(decision, findings) -> str`: Markdown cho `$GITHUB_STEP_SUMMARY`. Gồm bảng số lượng theo tool × severity, danh sách phát hiện bị chặn (chỉ tool, rule, file:line; **không in `message`**, vì message của Gitleaks có thể chứa secret) và chế độ đã dùng.
  - CLI `python security/gate/gate.py --sarif-dir sarif --changed-files changed.txt --mode traditional|ai-assisted [--report out/report.json] [--agent-exit N] [--labels a,b] [--workspace $GITHUB_WORKSPACE] [--summary $GITHUB_STEP_SUMMARY]`: trả mã thoát 1 khi `block`, 0 khi không. Không truyền `--changed-files` thì không lọc theo file (dùng cho main-ci).

- [ ] **Step 1: Tạo fixture SARIF nhỏ mô phỏng hình dạng của từng tool:**
  - `semgrep.sarif`: `level` ở result, `ruleId`.
  - `codeql.sarif`: `ruleIndex`, `security-severity` nằm ở rule.
  - `trivy.sarif`: `security-severity` ở rule, uri là `app/uv.lock`.
  - `gitleaks.sarif`: không có level.
  - `checkov.sarif`: uri tuyệt đối dạng `/github/workspace/infra/...`.
  - `corrupt.sarif`: JSON hỏng.
  - `report_ok.json`, `report_fp_critical.json`.
- [ ] **Step 2: Viết test thất bại:**

```python
def test_finding_id_format(): ...  # Finding("semgrep","r1","HIGH","app/a.py",3).id == "semgrep:r1:app/a.py:3"
@pytest.mark.parametrize("uri,ws,expected", [
    ("file:///github/workspace/app/a.py", None, "app/a.py"),
    ("/home/runner/work/x/x/infra/main.tf", "/home/runner/work/x/x", "infra/main.tf"),
    ("./app/b.py", None, "app/b.py"), ("app\\c.py", None, "app/c.py")])
def test_normalize_path(uri, ws, expected): ...
@pytest.mark.parametrize("score,sev", [("9.8","CRITICAL"),("7.0","HIGH"),("5.3","MEDIUM"),("1.0","LOW")])
def test_security_severity_from_rule(score, sev): ...
def test_level_fallback_and_gitleaks_always_high(): ...
def test_rule_lookup_by_rule_index(): ...           # codeql fixture
def test_result_without_location_is_kept(): ...      # file "" survives filter_changed
def test_missing_dir_or_file_means_no_findings(tmp_path): ...
def test_corrupt_sarif_blocks(tmp_path): ...         # errors non-empty → block
def test_traditional_blocks_high_in_changed_files_only(): ...
def test_ai_mode_falls_back_when_agent_failed(): ... # agent_exit=2 → mode_used "traditional (fallback)"
def test_ai_mode_unreviewed_high_blocks(): ...
def test_ai_mode_fp_unblocks_high_but_not_critical_without_label(): ...
def test_ai_mode_critical_fp_with_label_passes(): ...
def test_ai_mode_agent_new_tp_high_blocks(): ...      # confidence 0.8 blocks, 0.5 does not
def test_summary_never_contains_messages(): ...       # gitleaks message "AKIA..." absent
def test_cli_exit_codes(tmp_path): ...                # subprocess: 1 when blocking, 0 when clean
```

- [ ] **Step 3: Chạy** `uv run --with pytest pytest security/gate/tests -q`. Kỳ vọng: FAIL (`ModuleNotFoundError`). `conftest.py` thêm `security/gate` vào `sys.path`.
- [ ] **Step 4: Cài đặt** `gate.py` (chỉ dùng stdlib: `argparse`, `json`, `dataclasses`, `pathlib`).
- [ ] **Step 5: Chạy lại.** Kỳ vọng: toàn bộ PASS. Chạy thêm `uvx ruff check security/gate`, kỳ vọng sạch.
- [ ] **Step 6: Commit** `feat(gate): quality gate đọc SARIF, 2 chế độ traditional/ai-assisted`

---

### Task 3: Hạ tầng mẫu (Terraform AWS + Kubernetes), chỉ dùng để quét

**Files:**
- Create: `infra/terraform/{versions.tf, variables.tf, main.tf, outputs.tf}`, `infra/k8s/{namespace.yaml, deployment.yaml, service.yaml, networkpolicy.yaml}`, `infra/README.md`

**Interfaces:**
- Produces (cấu hình **an toàn theo thực hành tốt**, vì đây là bản sạch):
  - **Terraform:**
    - Provider `aws` pin `~> 6.0`, `required_version >= 1.9`.
    - VPC với 2 subnet private.
    - `aws_db_instance` PostgreSQL 16: `storage_encrypted = true`, `publicly_accessible = false`, `deletion_protection = true`, `backup_retention_period = 7`, `iam_database_authentication_enabled = true`, `auto_minor_version_upgrade = true`, mật khẩu do AWS quản lý (`manage_master_user_password = true`).
    - Bucket S3 lưu ảnh chụp `medicare-imaging`: `aws_s3_bucket_public_access_block` chặn cả 4 cờ, mã hóa SSE-KMS, bật versioning, bật logging sang bucket log.
    - Security group chỉ mở cổng 5432 cho SG của ứng dụng.
    - Không có secret dạng chữ.
  - **K8s:** namespace `medicare`; Deployment có:
    - `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`;
    - `resources.requests/limits`, `livenessProbe` và `readinessProbe` gọi `/health`;
    - image tham chiếu `ghcr.io/tuannguyen811/medicare-hms` kèm digest giả `@sha256:<64 số 0>` và ghi chú thay khi triển khai thật;
    - biến môi trường lấy từ `secretKeyRef` trỏ tới Secret `medicare-env`, **không commit manifest Secret**;
    - `automountServiceAccountToken: false`.
  - **Service** `ClusterIP`. **NetworkPolicy** chặn mọi ingress, trừ từ namespace ingress-controller.
  - **`infra/README.md`:** ghi rõ các file này **chỉ là đối tượng cho IaC Scan**, không `terraform apply`.

- [ ] **Step 1: Viết** các file theo Interfaces.
- [ ] **Step 2: Chạy** `docker run --rm -v "$PWD:/repo" bridgecrew/checkov:3.4.3 -d /repo/infra --framework terraform kubernetes --compact --quiet`. Ghi lại danh sách check FAILED. Check nào sửa được bằng cấu hình đúng thực hành (không phải comment skip) thì sửa. Check còn lại không hợp lý cho đồ án (ví dụ cross-region replication, VPC flow logs bắt buộc KMS riêng) thì giữ nguyên làm dữ liệu FP và ghi vào `docs/baseline-scan.md` ở Task 7.
- [ ] **Step 3: Chạy** `terraform fmt -check` và `terraform validate` qua image `hashicorp/terraform:1.9` (`init -backend=false`). Kỳ vọng: hợp lệ.
- [ ] **Step 4: Commit** `feat(infra): Terraform AWS và K8s manifest mẫu cho IaC Scan`

---

### Task 4: Pre-commit (Gitleaks + Ruff)

**Files:**
- Create: `.pre-commit-config.yaml`; Modify: `README.md` (thêm mục "Cho lập trình viên": `uv tool install pre-commit && pre-commit install`)

**Interfaces:**
- Produces:
  - Hook `gitleaks` từ `https://github.com/gitleaks/gitleaks`, `rev: v8.30.1`, id `gitleaks`, `args: ["--config", "security/gitleaks.toml"]`.
  - Hook `ruff` và `ruff-format --check` từ `astral-sh/ruff-pre-commit`, rev bản mới nhất, `files: ^(app|security)/`.

- [ ] **Step 1: Viết** config. Chạy `uvx pre-commit run --all-files`. Kỳ vọng: gitleaks Passed. Ruff có thể báo lỗi format, nếu có thì chạy `ruff format` trên `app/` và commit riêng.
- [ ] **Step 2: Kiểm thử thủ công:** tạo file tạm có chuỗi giống AWS key (`AKIA` + 16 ký tự hoa), `git add` rồi `uvx pre-commit run gitleaks`. Kỳ vọng: **Failed**. Xóa file tạm, **không commit nó**.
- [ ] **Step 3: Commit** `ci(pre-commit): chặn secret trước khi commit bằng Gitleaks`

---

### Task 5: Workflow `pr-security.yml`

**Files:**
- Create: `.github/workflows/pr-security.yml`

**Interfaces:**
- Consumes: `security/tool-versions.env`, `security/install-tools.sh`, `security/gate/gate.py`, `security/semgrep/medicare.yml`.
- Produces: trigger `pull_request` vào `main` (types: opened, synchronize, reopened, labeled), `concurrency: pr-security-${{ github.event.pull_request.number }}` với `cancel-in-progress: true`. Các job:
  - `build-test`: checkout, setup-uv có cache (`cache-dependency-glob: app/uv.lock`), `uv sync --frozen`, `uv run pytest -q`, `uv run ruff check`, `working-directory: app`.
  - `semgrep`: `semgrep scan --config p/python --config p/owasp-top-ten --config security/semgrep/medicare.yml --baseline-commit "$BASE_SHA" --sarif --output sarif/semgrep.sarif --metrics off app`.
  - `bandit`: `bandit -r app/medicare -f sarif -o sarif/bandit.sarif`, dùng `--exit-zero` để gate là nơi duy nhất ra quyết định.
  - `codeql`: `github/codeql-action/init` (`languages: python`, `build-mode: none`, `queries: security-extended`) rồi `analyze` (`output: sarif`, `upload: always`, `category: codeql`), sau đó copy file kết quả thành `sarif/codeql.sarif`.
  - `trivy`: `trivy fs --scanners vuln --format sarif --output sarif/trivy.sarif app/uv.lock`, cache DB theo khóa ngày `trivy-db-${{ steps.date.outputs.day }}`.
  - `gitleaks`: checkout `fetch-depth: 0`, `gitleaks git --log-opts="$BASE_SHA..$HEAD_SHA" --config security/gitleaks.toml --report-format sarif --report-path sarif/gitleaks.sarif --exit-code 0`.
  - `iac`: `checkov -d infra --file app/Dockerfile --config-file security/checkov.yaml -o sarif --output-file-path sarif`, đổi tên kết quả thành `sarif/checkov.sarif`; `zizmor --format sarif .github/workflows > sarif/zizmor.sarif`.
  - Mỗi job quét: upload artifact `sarif-<tool>`, rồi `github/codeql-action/upload-sarif` (`category: <tool>`) **chỉ khi** `github.event.pull_request.head.repo.full_name == github.repository`. Job đó có `permissions: security-events: write`.
  - `quality-gate` (`needs` mọi job quét và `build-test`, `if: always()`):
    - tải mọi artifact `sarif-*` vào `sarif/`;
    - tính `git diff --name-only "$BASE_SHA" "$HEAD_SHA" > changed.txt`;
    - chạy `python security/gate/gate.py --mode "${SECURITY_GATE_MODE:-traditional}" ...` với `SECURITY_GATE_MODE: ${{ vars.SECURITY_GATE_MODE }}`;
    - truyền labels qua biến môi trường `PR_LABELS: ${{ join(github.event.pull_request.labels.*.name, ',') }}` (không nhúng trực tiếp vào lệnh);
    - fail nếu `build-test` fail.
    - Để sẵn chỗ cho kế hoạch C: input `--report out/report.json` và `--agent-exit` chỉ được truyền khi có artifact `agent-report`.
  - `BASE_SHA` và `HEAD_SHA` đặt ở `env:` cấp workflow từ `github.event.pull_request.base.sha` và `.head.sha`. Không nhúng `${{ }}` vào `run:`.

- [ ] **Step 1: Viết** workflow. Lấy SHA của từng Action bằng `gh api`, kèm comment tag.
- [ ] **Step 2: Chạy** `actionlint` (binary từ Task 1, hoặc `docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.12`). Kỳ vọng: không lỗi. Chạy `uvx zizmor==1.32.0 .github/workflows`. Kỳ vọng: không còn lỗi mức medium trở lên (template injection, unpinned uses, excessive permissions).
- [ ] **Step 3: Commit, push nhánh, mở PR nháp.** Theo dõi bằng `gh pr checks --watch`. Kỳ vọng:
  - mọi job xanh;
  - `quality-gate` đạt, vì PR này không đụng `app/` nên không có phát hiện nào trong file thay đổi;
  - tab Security có kết quả theo từng category.
  Ghi lại thời gian chạy từng job.
- [ ] **Step 4: Kiểm thử gate trên CI bằng PR thử nghiệm** (nhánh tạm, không merge):
  - Thêm vào `app/medicare/patient/service.py` một hàm dùng `text(f"... {q}")`.
  - Kỳ vọng: `semgrep` (rule `medicare.sqlalchemy-text-fstring`) và `bandit` (B608) báo lỗi, `quality-gate` **đỏ**, job summary liệt kê đúng file:line.
  - Đóng PR, xóa nhánh tạm.
  - Ghi kết quả (ảnh hoặc link run) vào `docs/pipeline.md` ở Task 7.
- [ ] **Step 5: Commit** các chỉnh sửa phát sinh: `ci: pipeline bảo mật cho Pull Request`

---

### Task 6: Workflow `main-ci.yml` và `nightly-sca.yml`

**Files:**
- Create: `.github/workflows/main-ci.yml`, `.github/workflows/nightly-sca.yml`

**Interfaces:**
- Produces:
  - **`main-ci.yml`** (trigger `push` vào `main`, `workflow_dispatch`). Các job:
    - `build-test`.
    - `full-scan`: giống các job quét của PR nhưng **không** dùng `--baseline-commit` và không giới hạn commit range (gitleaks quét toàn bộ lịch sử). Upload SARIF lên tab Security (category `main-<tool>`). Không chặn: chỉ báo cáo.
    - `image`: `docker build -t medicare-hms:${{ github.sha }} app`; `trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed`; `trivy image --format cyclonedx --output sbom.cdx.json` rồi upload artifact; đăng nhập GHCR bằng `GITHUB_TOKEN` (`permissions: packages: write`); push `ghcr.io/${{ github.repository_owner }}/medicare-hms:{sha,latest}` (tên owner chuyển sang chữ thường trong một bước `run` dùng `env:`).
    - `staging` (`needs: image`):
      - sinh `app/.env` bằng `openssl rand` (SECRET_KEY, POSTGRES_PASSWORD, DEMO_PASSWORD), quyền file 600, không in ra log;
      - `docker compose -f infra/docker-compose.yml up -d --build`;
      - chờ `/health` tối đa 60 giây;
      - smoke test: `/health` → 200 `{"status":"ok"}`, `/login` → 200, `/patients` khi chưa đăng nhập → 303;
      - `docker compose exec -T app python -m medicare.seed` → mã thoát 0;
      - `down -v` (`if: always()`).
  - **`nightly-sca.yml`** (`schedule: cron "0 19 * * *"` tức 02:00 giờ Việt Nam, kèm `workflow_dispatch`): `trivy fs` trên `app/uv.lock` bằng DB mới nhất (không cache), upload SARIF với category `nightly-trivy`. Có thêm `trivy image ghcr.io/<owner>/medicare-hms:latest`.

- [ ] **Step 1: Viết** 2 workflow. Chạy actionlint và zizmor như Task 5. Kỳ vọng sạch.
- [ ] **Step 2: Kiểm thử bằng `workflow_dispatch` trên nhánh:** `gh workflow run main-ci.yml --ref feat/pipeline`, rồi `gh run watch`. Kỳ vọng:
  - các job xanh;
  - image có trên GHCR;
  - artifact SBOM tồn tại;
  - log staging cho thấy smoke test đạt.
  Nếu `trivy image` chặn do CVE Critical của base image đã có bản sửa, thì nâng base image lên patch mới nhất của `python:3.12-slim` trong `app/Dockerfile`. Không được hạ ngưỡng.
  Chạy `gh workflow run nightly-sca.yml --ref feat/pipeline`. Kỳ vọng: xanh.
- [ ] **Step 3: Commit** `ci: pipeline main (quét toàn bộ, image, SBOM, GHCR, staging) và quét SCA hằng đêm`

---

### Task 7: Đo bản sạch, tài liệu pipeline, branch protection

**Files:**
- Create: `docs/pipeline.md`, `docs/baseline-scan.md`, `security/scan-local.sh`

**Interfaces:**
- Produces:
  - **`security/scan-local.sh <out-dir>`:** chạy Semgrep, Bandit, Trivy, Gitleaks, Checkov và zizmor bằng **Docker image** đúng phiên bản trong `tool-versions.env` trên cây hiện tại, ghi `<out-dir>/<tool>.sarif`. Kế hoạch D sẽ dùng lại script này; CodeQL chạy trên CI. Image dùng:
    - `semgrep/semgrep:<v>`, `aquasec/trivy:<v>`, `zricethezav/gitleaks:v<v>`, `bridgecrew/checkov:<v>`;
    - Bandit và zizmor chạy trong `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` bằng `uvx`.
  - **`docs/baseline-scan.md`:** bảng phát hiện trên `v0.1-baseline` theo tool × severity, cộng danh sách từng phát hiện (tool, rule, file:line, nhận định ngắn: FP hay chấp nhận được). Lấy từ `scan-local.sh` + kết quả CodeQL của lần chạy `main-ci` (tải bằng `gh api .../code-scanning/alerts`). Đây là **mốc FP của bản sạch** cho thực nghiệm (RQ1).
  - **`docs/pipeline.md`:**
    - sơ đồ giai đoạn → công cụ (mục 3.1 của spec);
    - mô tả từng job, thời gian chạy đo được ở Task 5 và Task 6;
    - quy tắc gate (trích Hợp đồng 2);
    - các biện pháp bảo mật cho chính pipeline;
    - kết quả PR thử nghiệm SQLi của Task 5 Step 4.
  - **Branch protection cho `main`** (bằng `gh api -X PUT repos/{owner}/{repo}/branches/main/protection`):
    - required status checks `build-test` và `quality-gate` (strict);
    - `required_pull_request_reviews: null`;
    - `enforce_admins: false`;
    - `allow_force_pushes: false`, `allow_deletions: false`.
  - **Biến repo** `SECURITY_GATE_MODE=traditional` (`gh variable set`).

- [ ] **Step 1: Chạy** `bash security/scan-local.sh /tmp/baseline` trên tag `v0.1-baseline` (`git worktree add /tmp/bl v0.1-baseline`). Kỳ vọng: tạo đủ 6 file SARIF hợp lệ. Chạy `python security/gate/gate.py --sarif-dir /tmp/baseline --mode traditional`, ghi lại số lượng.
- [ ] **Step 2: Thêm test hồi quy** `test_parses_real_tool_output`: copy (rút gọn nếu lớn) SARIF thật của mỗi tool vào `security/gate/tests/fixtures/real/`, và test rằng `load_sarif` đọc được mọi file mà không lỗi. Kỳ vọng: PASS. Nếu FAIL thì sửa `gate.py` theo hình dạng thật.
- [ ] **Step 3: Viết** `docs/baseline-scan.md` và `docs/pipeline.md`.
- [ ] **Step 4: Bật branch protection và đặt biến repo.** Kiểm tra bằng `gh api repos/{owner}/{repo}/branches/main/protection --jq .required_status_checks.contexts`. Kỳ vọng: `["build-test","quality-gate"]`.
- [ ] **Step 5: Commit** `docs: kết quả quét bản sạch, mô tả pipeline; bật branch protection`
