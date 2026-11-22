#!/usr/bin/env bash
# Pull-based deploy of MediCare HMS to the local Kubernetes of Docker Desktop (spec addendum 6.4).
#
#   bash deploy/pull-deploy.sh [--digest sha256:<...>] [--skip-dast]
#
# CI never reaches this machine: this script pulls. Steps:
#   1. kube context must be docker-desktop;
#   2. resolve the digest of ghcr.io/tuannguyen811/medicare-hms:latest (or use --digest);
#   3. cosign: the image must be signed keyless by main-ci.yml on main of this repository and
#      carry a CycloneDX SBOM attestation from that identity, else stop before touching the
#      cluster;
#   4. first run: install Kyverno (release manifest verified by sha256) and its image policy,
#      which re-checks the same thing at admission; generate the secrets (never committed);
#   5. render deploy/local with that digest, apply, wait for the rollout;
#   6. smoke tests through kubectl port-forward on 127.0.0.1; on failure, rollout undo;
#   7. DAST: ZAP scans the deployed version with every role (security/dast/run-dast.sh).
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
PORT="18000"
ZERO="sha256:0000000000000000000000000000000000000000000000000000000000000000"

digest="" skip_dast=0
while [ $# -gt 0 ]; do
  case "$1" in
    --digest) digest="$2"; shift 2 ;;
    --skip-dast) skip_dast=1; shift ;;
    *) echo "pull-deploy.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*" >&2; }
fail() { echo "pull-deploy.sh: $*" >&2; exit 1; }

# --- 1. context and tools -------------------------------------------------------------------
[ "$(kubectl config current-context)" = "docker-desktop" ] \
  || fail "kube context must be docker-desktop (got $(kubectl config current-context))"
bash "$here/install-tools.sh"
cosign="$here/.tools/cosign"
[ -x "$cosign" ] || cosign="$here/.tools/cosign.exe"
py="$(command -v python3 || command -v python)"

# --- 2. digest ------------------------------------------------------------------------------
if [ -z "$digest" ]; then
  digest="$(docker buildx imagetools inspect "$IMAGE:latest" --format '{{.Manifest.Digest}}')"
fi
case "$digest" in sha256:[0-9a-f]*) ;; *) fail "not a digest: $digest" ;; esac
ref="$IMAGE@$digest"
say "Image $ref"

# --- 3. signature and SBOM attestation ------------------------------------------------------
say "cosign: signature and CycloneDX attestation from main-ci.yml on main"
"$cosign" verify "$ref" --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  >/dev/null || fail "signature check failed: refusing to deploy $ref"
"$cosign" verify-attestation "$ref" --type cyclonedx --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" >/dev/null \
  || fail "SBOM attestation check failed: refusing to deploy $ref"

# --- 4. Kyverno, policy, secrets ------------------------------------------------------------
if ! kubectl get crd imagevalidatingpolicies.policies.kyverno.io >/dev/null 2>&1; then
  say "Installing Kyverno $KYVERNO_VERSION"
  manifest="$here/.tools/kyverno-$KYVERNO_VERSION.yaml"
  curl -fsSL --retry 3 -o "$manifest" \
    "https://github.com/kyverno/kyverno/releases/download/v${KYVERNO_VERSION}/install.yaml"
  echo "$KYVERNO_INSTALL_SHA256  $manifest" | sha256sum -c --quiet - \
    || fail "Kyverno install.yaml does not match its pinned sha256"
  # Same images, same digests, served by GHCR: pulls from reg.kyverno.io break inside the
  # Docker Desktop node ("short read: unexpected EOF").
  sed 's#reg\.kyverno\.io/kyverno/#ghcr.io/kyverno/#g' "$manifest" \
    | kubectl apply --server-side --force-conflicts -f - >/dev/null
  kubectl -n kyverno rollout status deploy --timeout=600s
fi
kubectl apply -f "$here/kyverno/image-policy.yaml" >/dev/null

kubectl apply -f "$root/infra/k8s/namespace.yaml" >/dev/null
first_deploy=0
if ! kubectl -n "$NS" get secret medicare-db >/dev/null 2>&1; then
  say "First deploy: generating secrets (stored in the cluster only)"
  first_deploy=1
  rand() { openssl rand -hex "$1"; }
  pg="$(rand 24)" demo="Demo-$(rand 12)"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  ( umask 077
    printf 'user=medicare\ndb=medicare\npassword=%s\n' "$pg" > "$tmp/db.env"
    { echo "ENV=development"
      echo "SECRET_KEY=$(rand 48)"
      echo "DATABASE_URL=postgresql+psycopg://medicare:${pg}@medicare-db:5432/medicare"
      echo "DEMO_PASSWORD=${demo}"
    } > "$tmp/app.env" )
  kubectl -n "$NS" create secret generic medicare-db --from-env-file="$tmp/db.env" >/dev/null
  kubectl -n "$NS" create secret generic medicare-env --from-env-file="$tmp/app.env" >/dev/null
  rm -rf "$tmp"
  echo "Demo password for every demo account (shown once): $demo" >&2
fi

# --- 5. render, apply, rollout ----------------------------------------------------------------
say "Applying deploy/local"
rendered="$(kubectl kustomize --load-restrictor LoadRestrictionsNone "$here/local" \
  | sed "s#${IMAGE}@${ZERO}#${ref}#g")"
case "$rendered" in *"$ZERO"*) fail "the placeholder digest is still in the manifests" ;; esac
had_app=0
kubectl -n "$NS" get deploy medicare-app >/dev/null 2>&1 && had_app=1
printf '%s\n' "$rendered" | kubectl apply -f - >/dev/null

rollback() {
  echo "pull-deploy.sh: $*" >&2
  if [ "$had_app" = 1 ]; then
    echo "pull-deploy.sh: rolling back to the previous revision" >&2
    kubectl -n "$NS" rollout undo deploy/medicare-app || true
  fi
  exit 1
}
kubectl -n "$NS" rollout status statefulset/medicare-db --timeout=180s \
  || rollback "database did not become ready"
kubectl -n "$NS" rollout status deploy/medicare-app --timeout=180s \
  || rollback "app rollout did not complete"
if [ "$first_deploy" = 1 ]; then
  say "Seeding demo data"
  kubectl -n "$NS" exec deploy/medicare-app -- python -m medicare.seed
fi

# --- 6. smoke tests -------------------------------------------------------------------------------
say "Smoke tests on http://127.0.0.1:$PORT (kubectl port-forward)"
kubectl -n "$NS" port-forward --address 127.0.0.1 svc/medicare-app "$PORT:80" >/dev/null 2>&1 &
pf=$!
trap 'kill "$pf" 2>/dev/null || true' EXIT
base="http://127.0.0.1:$PORT"
for _ in $(seq 1 30); do
  curl -fsS "$base/health" >/dev/null 2>&1 && break
  sleep 1
done
code() { curl -s -o /dev/null -w '%{http_code}' "$base$1"; }
[ "$(curl -fsS "$base/health" 2>/dev/null)" = '{"status":"ok"}' ] || rollback "smoke: /health"
[ "$(code /login)" = 200 ] || rollback "smoke: /login is not 200"
[ "$(code /patients)" = 303 ] || rollback "smoke: /patients does not redirect anonymous users"
[ "$(code /api/v1/patients/1)" = 401 ] || rollback "smoke: the API does not require authentication"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $ref deployed" >> "$here/.history"
say "Deployed $ref"

# --- 7. DAST on the deployed version --------------------------------------------------------------
if [ "$skip_dast" = 1 ]; then
  exit 0
fi
work="$here/reports/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$work"
say "DAST (ZAP, every role) -> $work"
kubectl -n "$NS" exec -i deploy/medicare-app -- python - --stdout \
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
