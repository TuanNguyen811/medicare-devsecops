#!/usr/bin/env bash
# Install the pinned cosign for this machine (Windows under Git Bash, or Linux x64) into
# deploy/.tools/, verifying its sha256 (security/tool-versions.env).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=../security/tool-versions.env
. "$here/../security/tool-versions.env"

tools="$here/.tools"
mkdir -p "$tools"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) asset="cosign-windows-amd64.exe"; sum="$COSIGN_WINDOWS_SHA256"; bin="cosign.exe" ;;
  Linux) asset="cosign-linux-amd64"; sum="$COSIGN_SHA256"; bin="cosign" ;;
  *) echo "install-tools.sh: unsupported OS $(uname -s)" >&2; exit 2 ;;
esac

if [ -x "$tools/$bin" ] && echo "$sum  $tools/$bin" | sha256sum -c --quiet - 2>/dev/null; then
  exit 0
fi
curl -fsSL --retry 3 -o "$tools/$bin.part" \
  "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/${asset}"
echo "$sum  $tools/$bin.part" | sha256sum -c --quiet -
mv "$tools/$bin.part" "$tools/$bin"
chmod +x "$tools/$bin"
echo "installed cosign ${COSIGN_VERSION} -> $tools/$bin" >&2
