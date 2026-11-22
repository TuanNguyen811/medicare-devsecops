#!/usr/bin/env bash
# DAST with OWASP ZAP, one authenticated scan per role (spec addendum 5.1).
#
#   DEMO_PASSWORD=... bash security/dast/run-dast.sh --target http://app:8000 \
#     --network dast_default --work dast-out [--roles "DOCTOR PATIENT"]
#
# <work> must already hold openapi.json and routes.json (export_routes.py). The ZAP container
# joins the Docker network of the app, logs in with login.py, then runs zap-plan.yaml.
# Output: <work>/out/zap-<ROLE>.json for each role and <work>/zap.sarif (zap2sarif.py).
# Each role gets one retry; the script exits non-zero if any role still has no report, or if
# its session was no longer logged in at the end of the scan (it would have scanned as a guest).
# ADMIN always runs last: its active scan can deactivate accounts the other roles log in with.
# Used by the PR pipeline, the local deploy (phase 3) and the benchmark (phase 5).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$here/../.." && pwd -P)"
# shellcheck source=../tool-versions.env
. "$root/security/tool-versions.env"

target="" network="" work="" roles="RECEPTIONIST DOCTOR NURSE PATIENT ADMIN"
while [ $# -gt 0 ]; do
  case "$1" in
    --target) target="$2"; shift 2 ;;
    --network) network="$2"; shift 2 ;;
    --work) work="$2"; shift 2 ;;
    --roles) roles="$2"; shift 2 ;;
    *) echo "run-dast.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
if [ -z "$target" ] || [ -z "$network" ] || [ -z "$work" ]; then
  echo "usage: run-dast.sh --target URL --network NET --work DIR [--roles \"ROLE ...\"]" >&2
  exit 2
fi
if [ -z "${DEMO_PASSWORD:-}" ]; then
  echo "run-dast.sh: DEMO_PASSWORD is not set" >&2
  exit 2
fi
for f in openapi.json routes.json; do
  [ -s "$work/$f" ] || { echo "run-dast.sh: missing $work/$f (run export_routes.py)" >&2; exit 2; }
done

user_of() {
  case "$1" in
    ADMIN) echo admin ;;
    RECEPTIONIST) echo letan1 ;;
    DOCTOR) echo bacsi1 ;;
    NURSE) echo yta1 ;;
    PATIENT) echo benhnhan1 ;;
    *) return 1 ;;
  esac
}

# ADMIN last, whatever the order given.
ordered=""
for role in $roles; do [ "$role" = ADMIN ] || ordered="$ordered $role"; done
case " $roles " in *" ADMIN "*) ordered="$ordered ADMIN" ;; esac
roles="$ordered"

mkdir -p "$work/out"
cp "$here/login.py" "$here/zap-plan.yaml" "$work/"
# The ZAP image runs as its own user: it must be able to write the reports.
chmod -R a+rwX "$work"
mount="$(cd "$work" && (pwd -W 2>/dev/null || pwd -P))"  # Windows path under Git Bash

zap() {
  MSYS_NO_PATHCONV=1 docker run --rm --network "$network" -v "$mount:/zap/wrk:rw" "$@"
}

scan_role() {
  local role="$1" user creds cookie csrf
  user="$(user_of "$role")" || { echo "run-dast.sh: unknown role $role" >&2; return 1; }
  rm -f "$work/out/zap-$role.json"
  if ! creds="$(zap -e DEMO_PASSWORD "$ZAP_IMAGE" python3 /zap/wrk/login.py "$target" "$user")"; then
    echo "run-dast.sh: login failed for $role" >&2
    return 1
  fi
  cookie="$(printf '%s\n' "$creds" | sed -n 's/^ZAP_COOKIE=//p')"
  csrf="$(printf '%s\n' "$creds" | sed -n 's/^ZAP_CSRF=//p')"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::add-mask::$cookie"
    echo "::add-mask::$csrf"
  fi
  set +e
  ZAP_COOKIE="$cookie" ZAP_CSRF="$csrf" TARGET="$target" ROLE="$role" \
    zap -e ZAP_COOKIE -e ZAP_CSRF -e TARGET -e ROLE "$ZAP_IMAGE" \
    zap.sh -cmd -autorun /zap/wrk/zap-plan.yaml
  local code=$?
  set -e
  # 0 = done, 2 = done with job warnings; anything else, or no report, is a failure.
  if [ "$code" -ne 0 ] && [ "$code" -ne 2 ]; then
    echo "run-dast.sh: ZAP exited $code for $role" >&2
    return 1
  fi
  [ -s "$work/out/zap-$role.json" ] || { echo "run-dast.sh: no report for $role" >&2; return 1; }
  if ! ZAP_COOKIE="$cookie" zap -e ZAP_COOKIE "$ZAP_IMAGE" \
      python3 /zap/wrk/login.py --check "$target"; then
    echo "run-dast.sh: $role was logged out during the scan; its report is not trusted" >&2
    return 1
  fi
}

failed=0
reports=()
for role in $roles; do
  start=$(date +%s)
  if scan_role "$role" || { echo "run-dast.sh: retrying $role" >&2; scan_role "$role"; }; then
    echo "run-dast.sh: $role done in $(( $(date +%s) - start )) s" >&2
    reports+=("$role=$work/out/zap-$role.json")
  else
    echo "::error::DAST scan failed for role $role" >&2
    failed=1
  fi
done

py="$(command -v python3 || command -v python)"
if [ "${#reports[@]}" -gt 0 ]; then
  "$py" "$here/zap2sarif.py" --routes "$work/routes.json" --out "$work/zap.sarif" "${reports[@]}"
fi
exit "$failed"
