#!/usr/bin/env bash
# Run the scanners locally with Docker, pinned to security/tool-versions.env.
# Scans an export of the committed tree (git archive), so untracked files such as .venv
# or a local .env with real secrets are never scanned. CodeQL runs in CI only.
#
# Usage: bash security/scan-local.sh <out-dir> [git-ref=HEAD] [repo-dir=.]
# Output: <out-dir>/{semgrep,bandit,trivy,gitleaks,checkov,zizmor}.sarif
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$here/tool-versions.env"

out_arg="${1:?usage: scan-local.sh <out-dir> [git-ref] [repo-dir]}"
ref="${2:-HEAD}"
repo="$(cd "${3:-$here/..}" && pwd)"
mkdir -p "$out_arg"
out="$(cd "$out_arg" && pwd)"

src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT
git -C "$repo" archive --format=tar "$ref" | tar -x -C "$src"

# Docker on Windows (Git Bash) needs native paths and no MSYS path mangling.
host() { if (cd "$1" && pwd -W) >/dev/null 2>&1; then (cd "$1" && pwd -W); else echo "$1"; fi; }
export MSYS_NO_PATHCONV=1
SRC="$(host "$src")"
OUT="$(host "$out")"
run() { docker run --rm -v "$SRC:/src" -v "$OUT:/out" -w /src "$@"; }
UV_IMAGE="ghcr.io/astral-sh/uv:python3.12-bookworm-slim"

echo "[1/6] semgrep ${SEMGREP_VERSION}"
run "semgrep/semgrep:${SEMGREP_VERSION}" semgrep scan --metrics off --quiet --disable-nosem \
  --config p/python --config p/owasp-top-ten --config security/semgrep/medicare.yml \
  --sarif --output /out/semgrep.sarif app agent/src

echo "[2/6] bandit ${BANDIT_VERSION}"
run "$UV_IMAGE" uvx --quiet --exclude-newer "$TOOLS_EXCLUDE_NEWER" \
  --from "bandit[sarif]==${BANDIT_VERSION}" \
  bandit -q -r app/medicare agent/src --ignore-nosec -f sarif -o /out/bandit.sarif --exit-zero

echo "[3/6] trivy ${TRIVY_VERSION}"
run "aquasec/trivy:${TRIVY_VERSION}" fs --quiet --scanners vuln \
  --format sarif --output /out/trivy.sarif .

echo "[4/6] gitleaks ${GITLEAKS_VERSION} (files of the tree)"
run "zricethezav/gitleaks:v${GITLEAKS_VERSION}" dir --config security/gitleaks.toml --ignore-gitleaks-allow \
  --redact --exit-code 0 --no-banner --report-format sarif --report-path /out/gitleaks.sarif .

echo "[5/6] checkov ${CHECKOV_VERSION}"
run "bridgecrew/checkov:${CHECKOV_VERSION}" -d . --config-file security/checkov.yaml \
  -o sarif --output-file-path /out/checkov-raw --soft-fail --quiet > /dev/null
mv "$out/checkov-raw/results_sarif.sarif" "$out/checkov.sarif"
rm -rf "$out/checkov-raw"

echo "[6/6] zizmor ${ZIZMOR_VERSION}"
run "$UV_IMAGE" sh -c "uvx --quiet --exclude-newer ${TOOLS_EXCLUDE_NEWER} \
  zizmor==${ZIZMOR_VERSION} --offline --format sarif . > /out/zizmor.sarif \
  || test -s /out/zizmor.sarif"

echo "SARIF written to $out"
