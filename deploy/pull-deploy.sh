#!/usr/bin/env bash
# Pull-based deploy of MediCare HMS to the local Kubernetes of Docker Desktop (spec addendum 6.4).
#
#   bash deploy/pull-deploy.sh [--digest sha256:<64 hex>] [--dast]
#
# CI never reaches this machine: this script pulls. Steps:
#   1. kube context must be docker-desktop;
#   2. resolve the digest of ghcr.io/tuannguyen811/medicare-hms:latest (or use --digest);
#   3. cosign: the image must be signed keyless by main-ci.yml on main of this repository and
#      carry a CycloneDX SBOM attestation from that identity, else stop before touching the
#      cluster;
#   4. Kyverno (release manifest verified by sha256) and its image policy, which re-checks the
#      same thing at admission; any missing secret is generated (never committed);
#   5. render deploy/local with that digest, apply, wait for the rollout, seed (idempotent);
#   6. smoke tests on the new pod through kubectl port-forward on 127.0.0.1; on failure, roll
#      back if this run changed the running version;
#   7. with --dast only: ZAP scans the deployed version with every role (~25 min; every PR
#      was already scanned by the PR pipeline before merge).
# There is deliberately no option to skip the signature checks.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$here/.." && pwd -P)"
# shellcheck source=../security/tool-versions.env
. "$root/security/tool-versions.env"

IMAGE="ghcr.io/tuannguyen811/medicare-hms"
IDENTITY="https://github.com/TuanNguyen811/medicare-devsecops/.github/workflows/main-ci.yml@refs/heads/main"
ISSUER="https://token.actions.githubusercontent.com"
NS="medicare"
PORT="18001"  # script-only port: users' own port-forwards use 18000 (README)
ZERO="sha256:0000000000000000000000000000000000000000000000000000000000000000"

usage() { echo "usage: pull-deploy.sh [--digest sha256:<64 hex>] [--dast]" >&2; exit 2; }
digest="" dast=0
while [ $# -gt 0 ]; do
  case "$1" in
    --digest) [ $# -ge 2 ] || usage; digest="$2"; shift 2 ;;
    --dast) dast=1; shift ;;
    *) usage ;;
  esac
done

say() { printf '\n==> %s\n' "$*" >&2; }
fail() { echo "pull-deploy.sh: $*" >&2; exit 1; }

pf=""
tmp="$(mktemp -d)"
cleanup() {
  if [ -n "$pf" ]; then
    kill "$pf" 2>/dev/null || true  # the restart loop first, then its kubectl
    [ -f "$tmp/pf.pid" ] && kill "$(cat "$tmp/pf.pid")" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

# kubectl port-forward exits on the first broken connection, which a ZAP active scan provokes
# within minutes: keep it alive in a restart loop for the whole smoke test + DAST.
forward() {  # forward <pod>
  while :; do
    kubectl -n "$NS" port-forward --address 127.0.0.1 "pod/$1" "$PORT:8000" >/dev/null 2>&1 &
    echo $! > "$tmp/pf.pid"
    wait "$!" || true
    sleep 1
  done
}

# --- 1. context and tools -------------------------------------------------------------------
[ "$(kubectl config current-context)" = "docker-desktop" ] \
  || fail "kube context must be docker-desktop (got $(kubectl config current-context))"
bash "$here/install-tools.sh"
cosign="$here/.tools/cosign"
[ -x "$cosign" ] || cosign="$here/.tools/cosign.exe"
py=""
for candidate in python3 python; do  # skip the Windows Store alias, which is not Python
  if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys' 2>/dev/null; then
    py="$(command -v "$candidate")"; break
  fi
done
[ -n "$py" ] || fail "python is required"

# --- 2. digest ------------------------------------------------------------------------------
if [ -z "$digest" ]; then
  digest="$(docker buildx imagetools inspect "$IMAGE:latest" --format '{{.Manifest.Digest}}')"
fi
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "not a sha256 digest: $digest"
ref="$IMAGE@$digest"
say "Image $ref"

# --- 3. signature and SBOM attestation ------------------------------------------------------
say "cosign: signature and CycloneDX attestation from main-ci.yml on main"
verify_flags=(--certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
              --certificate-github-workflow-ref refs/heads/main)
"$cosign" verify "$ref" "${verify_flags[@]}" >/dev/null \
  || fail "signature check failed: refusing to deploy $ref"
"$cosign" verify-attestation "$ref" --type cyclonedx "${verify_flags[@]}" >/dev/null \
  || fail "SBOM attestation check failed: refusing to deploy $ref"

# --- 4. Kyverno, policy, secrets ------------------------------------------------------------
if ! kubectl -n kyverno get deploy kyverno-admission-controller >/dev/null 2>&1; then
  say "Installing Kyverno $KYVERNO_VERSION"
  manifest="$here/.tools/kyverno-$KYVERNO_VERSION.yaml"
  curl -fsSL --retry 3 -o "$manifest" \
    "https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_VERSION}/install.yaml"
  echo "$KYVERNO_INSTALL_SHA256  $manifest" | sha256sum -c --quiet - \
    || fail "Kyverno install.yaml does not match its pinned sha256"
  # The same Kyverno release images are published on GHCR (identical digests when pinned on
  # 2026-11-22); pulls from reg.kyverno.io break inside the Docker Desktop node
  # ("short read: unexpected EOF").
  sed 's#reg\.kyverno\.io/kyverno/#ghcr.io/kyverno/#g' "$manifest" \
    | kubectl apply --server-side --force-conflicts -f - >/dev/null
fi
for d in $(kubectl -n kyverno get deploy -o name); do
  kubectl -n kyverno rollout status "$d" --timeout=600s >/dev/null
done
kubectl apply -f "$here/kyverno/image-policy.yaml" >/dev/null
# The admission webhook must be serving before any pod is created. (The policy's overall
# "ready" stays false because the reports controller lacks RBAC on pods/ephemeralcontainers;
# that only affects background reports, not admission.)
for _ in $(seq 1 60); do
  hook="$(kubectl get imagevalidatingpolicy medicare-signed-images -o     jsonpath='{.status.conditionStatus.conditions[?(@.type=="WebhookConfigured")].status}'     2>/dev/null || true)"
  [ "$hook" = "True" ] && break
  sleep 2
done
[ "$hook" = "True" ] || fail "Kyverno has not configured the webhook of medicare-signed-images"

kubectl apply -f "$root/infra/k8s/namespace.yaml" >/dev/null
rand() { openssl rand -hex "$1"; }
if ! kubectl -n "$NS" get secret medicare-db >/dev/null 2>&1; then
  say "Generating secret medicare-db (stored in the cluster only)"
  ( umask 077; printf 'user=medicare\ndb=medicare\npassword=%s\n' "$(rand 24)" > "$tmp/db.env" )
  kubectl -n "$NS" create secret generic medicare-db --from-env-file="$tmp/db.env" >/dev/null
fi
if ! kubectl -n "$NS" get secret medicare-env >/dev/null 2>&1; then
  say "Generating secret medicare-env (stored in the cluster only)"
  pg="$(kubectl -n "$NS" get secret medicare-db -o jsonpath='{.data.password}' | base64 -d)"
  demo="Demo-$(rand 12)"
  ( umask 077
    { echo "ENV=development"
      echo "SECRET_KEY=$(rand 48)"
      echo "DATABASE_URL=postgresql+psycopg://medicare:${pg}@medicare-db:5432/medicare"
      echo "DEMO_PASSWORD=${demo}"
    } > "$tmp/app.env" )
  kubectl -n "$NS" create secret generic medicare-env --from-env-file="$tmp/app.env" >/dev/null
  echo "Demo password for every demo account (shown once): $demo" >&2
fi
rm -f "$tmp"/*.env

# --- 5. render, apply, rollout, seed ----------------------------------------------------------
say "Applying deploy/local"
rendered="$(kubectl kustomize --load-restrictor LoadRestrictionsNone "$here/local" \
  | sed "s#${IMAGE}@${ZERO}#${ref}#g")"
case "$rendered" in *"$ZERO"*) fail "the placeholder digest is still in the manifests" ;; esac
case "$rendered" in *"$ref"*) ;; *) fail "the verified digest is not in the manifests" ;; esac
previous="$(kubectl -n "$NS" get deploy medicare-app \
  -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)"
printf '%s\n' "$rendered" | kubectl apply -f - >/dev/null

rollback() {
  echo "pull-deploy.sh: $*" >&2
  # Only undo what this run changed: redeploying the running digest must not go back further.
  if [ -n "$previous" ] && [ "$previous" != "$ref" ]; then
    echo "pull-deploy.sh: rolling back to $previous" >&2
    kubectl -n "$NS" rollout undo deploy/medicare-app || true
  fi
  exit 1
}
kubectl -n "$NS" rollout status statefulset/medicare-db --timeout=300s \
  || rollback "database did not become ready"
kubectl -n "$NS" rollout status deploy/medicare-app --timeout=300s \
  || rollback "app rollout did not complete"

# The new pod (running the verified digest, not terminating): smoke tests, seed and the route
# export must not reach a pod of the previous version that is still shutting down.
pod=""
for _ in $(seq 1 60); do
  pod="$(kubectl -n "$NS" get pods -l app=medicare -o jsonpath="{range .items[?(@.spec.containers[0].image=='${ref}')]}{.metadata.name} {.metadata.deletionTimestamp} {.status.phase}{'\n'}{end}" \
    | awk 'NF == 2 && $2 == "Running" {print $1; exit}')"
  [ -n "$pod" ] && break
  sleep 2
done
[ -n "$pod" ] || rollback "no running pod with the new image"
say "Seeding demo data (no-op when it already exists)"
kubectl -n "$NS" exec "pod/$pod" -- python -m medicare.seed || rollback "seed failed"

# --- 6. smoke tests -------------------------------------------------------------------------------
say "Smoke tests on http://127.0.0.1:$PORT (kubectl port-forward to $pod)"
if curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then
  fail "port $PORT is already in use on 127.0.0.1"
fi
forward "$pod" &
pf=$!
base="http://127.0.0.1:$PORT"
for _ in $(seq 1 30); do
  curl -fsS "$base/health" >/dev/null 2>&1 && break
  sleep 1
done
kill -0 "$pf" 2>/dev/null || rollback "kubectl port-forward exited"
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
[ "$(curl -fsS "$base/health" 2>/dev/null)" = '{"status":"ok"}' ] || rollback "smoke: /health"
[ "$(code /login)" = 200 ] || rollback "smoke: /login is not 200"
[ "$(code /patients)" = 303 ] || rollback "smoke: /patients does not redirect anonymous users"
[ "$(code /api/v1/patients/1)" = 401 ] || rollback "smoke: the API does not require authentication"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $ref deployed" >> "$here/.history"
say "Deployed $ref"

# --- 7. DAST on the deployed version --------------------------------------------------------------
if [ "$dast" != 1 ]; then
  exit 0
fi
work="$here/reports/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$work"
say "DAST (ZAP, every role) -> $work"
kubectl -n "$NS" exec -i "pod/$pod" -- python - --stdout \
  < "$root/security/dast/export_routes.py" > "$work/bundle.json"
"$py" "$root/security/dast/export_routes.py" --split "$work/bundle.json" "$work"
DEMO_PASSWORD="$(kubectl -n "$NS" get secret medicare-env -o jsonpath='{.data.DEMO_PASSWORD}' \
  | base64 -d)"
export DEMO_PASSWORD
# The ZAP container reaches the port-forward on this machine through host.docker.internal.
bash "$root/security/dast/run-dast.sh" --target "http://host.docker.internal:$PORT" \
  --network bridge --work "$work" || fail "DAST did not complete; see $work"
"$py" - "$work/zap.sarif" <<'EOF'
import json, sys
results = json.load(open(sys.argv[1], encoding="utf-8"))["runs"][0]["results"]
levels = {"8.0": "HIGH", "5.0": "MEDIUM", "2.0": "LOW"}
counts = {}
for r in results:
    level = levels.get(r["properties"]["security-severity"], "?")
    counts[level] = counts.get(level, 0) + 1
print("DAST results:", ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
if counts.get("HIGH"):
    print("WARNING: HIGH findings on the deployed version", file=sys.stderr)
EOF
