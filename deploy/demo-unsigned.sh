#!/usr/bin/env bash
# Demo: the cluster refuses a MediCare image that main-ci did not sign on main (spec 6.4).
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
set +e
out="$(kubectl -n medicare run demo-unsigned --image="$image" --restart=Never \
  --dry-run=server --overrides="$overrides" 2>&1)"
code=$?
set -e
echo "$out" >&2
if [ "$code" -eq 0 ]; then
  echo "UNEXPECTED: the cluster accepted an image that main-ci did not sign on main." >&2
  exit 1
fi
# Any other refusal (no namespace, Pod Security, Kyverno missing) is not this demo.
case "$out" in
  *medicare-signed-images*)
    echo "As expected: Kyverno (policy medicare-signed-images) refused the image." >&2 ;;
  *)
    echo "Refused, but not by the Kyverno image policy: check the cluster setup." >&2
    exit 1 ;;
esac
