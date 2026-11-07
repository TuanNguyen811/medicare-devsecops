#!/usr/bin/env bash
# Install pinned scanner binaries (Linux x64) into DEST, verifying sha256.
# Usage: bash security/install-tools.sh <dest-dir>
set -euo pipefail

dest="${1:?usage: install-tools.sh <dest-dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$here/tool-versions.env"

mkdir -p "$dest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() {  # fetch <url> <sha256> <archive-name>
  curl -fsSL --retry 3 -o "$work/$3" "$1"
  echo "$2  $work/$3" | sha256sum -c --quiet -
  tar -xzf "$work/$3" -C "$work"
}

fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
  "$TRIVY_SHA256" trivy.tar.gz
fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
  "$GITLEAKS_SHA256" gitleaks.tar.gz
fetch "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" \
  "$ACTIONLINT_SHA256" actionlint.tar.gz

install -m 0755 "$work/trivy" "$work/gitleaks" "$work/actionlint" "$dest/"
echo "installed: trivy ${TRIVY_VERSION}, gitleaks ${GITLEAKS_VERSION}, actionlint ${ACTIONLINT_VERSION} -> $dest"
