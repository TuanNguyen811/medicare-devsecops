#!/usr/bin/env bash
# Chạy engine claude-code trên máy (benchmark, demo) giống hệt bước engine trên CI.
# Cách dùng: agent/scripts/claude-engine.sh <repo> <out>
#   <out>/context/task.md do `secagent-prepare` tạo trước; kết quả ghi vào
#   <out>/engine-execution.jsonl để `secagent-finalize --execution-file` đọc.
# Engine chỉ được Read/Grep/Glob trong repo, chế độ dontAsk (agent/engine.env).
# Không in token hay biến môi trường.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "Cách dùng: $0 <repo> <out>" >&2
  exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=../engine.env
. "$here/../engine.env"

repo="$(cd "$1" && pwd -P)"
mkdir -p "$2"
out="$(cd "$2" && pwd -P)"

extra=()
case "$out/" in
  "$repo"/*) task="${out#"$repo"/}/context/task.md" ;;
  *) task="$out/context/task.md"; extra=(--add-dir "$out") ;;
esac
prompt="${CLAUDE_ENGINE_PROMPT//\{task\}/$task}"

read -r -a isolation <<< "$CLAUDE_ENGINE_ISOLATION"

cd "$repo"
# ${extra[@]+...}: an empty array is an "unbound variable" under set -u in bash < 4.4.
timeout 1200 "${CLAUDE_BIN:-claude}" -p "$prompt" \
  --model "$CLAUDE_ENGINE_MODEL" \
  --tools "$CLAUDE_ENGINE_TOOLS" \
  --permission-mode "$CLAUDE_ENGINE_PERMISSION_MODE" \
  --allowedTools "$CLAUDE_ENGINE_ALLOWED_TOOLS" \
  --disallowedTools "$CLAUDE_ENGINE_DISALLOWED_TOOLS" \
  --max-turns "$CLAUDE_ENGINE_MAX_TURNS" \
  "${isolation[@]}" \
  --output-format stream-json --verbose \
  ${extra[@]+"${extra[@]}"} > "$out/engine-execution.jsonl"
