#!/usr/bin/env bash
# Demo: the cluster refuses a MediCare image that main-ci did not sign on main (spec addendum 6.4).
#
#   bash deploy/demo-unsigned.sh [image@sha256:...]
#
# Default: the last image pushed before signing existed (never signed). Pass the digest of an
# image built by a branch (signed, but by the wrong identity) to show that case too.
# Uses a server-side dry run: Kyverno's admission webhook decides, nothing is created.
set -euo pipefail

image="${1:-ghcr.io/tuannguyen811/medicare-hms@sha256:2171806b439e0cdb287a9c799c6af31748312b01b8093a173b9cfd928b57ea40}"
overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":10001,
  "seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"app","image":"'"$image"'",
  "securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}'

echo "Trying to run $image in namespace medicare ..." >&2
if kubectl -n medicare run demo-unsigned --image="$image" --restart=Never --dry-run=server \
     --overrides="$overrides"; then
  echo "UNEXPECTED: the cluster accepted an image that main-ci did not sign on main." >&2
  exit 1
fi
echo "As expected: Kyverno refused the image." >&2
