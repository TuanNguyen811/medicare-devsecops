#!/usr/bin/env bash
# Chạy engine claude-code trên máy (benchmark, demo) giống hệt bước engine trên CI.
# Cách dùng: agent/scripts/claude-engine.sh <repo> <out>
#   <out>/context/task.md do `secagent-prepare` tạo trước; kết quả ghi vào
#   <out>/engine-execution.jsonl để `secagent-finalize --execution-file` đọc.
# Engine chỉ được Read/Grep/Glob (agent/engine.env). Không in token hay biến môi trường.
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

cd "$repo"
timeout 1200 "${CLAUDE_BIN:-claude}" -p "$prompt" \
  --model "$CLAUDE_ENGINE_MODEL" \
  --allowedTools "$CLAUDE_ENGINE_ALLOWED_TOOLS" \
  --disallowedTools "$CLAUDE_ENGINE_DISALLOWED_TOOLS" \
  --max-turns "$CLAUDE_ENGINE_MAX_TURNS" \
  --output-format stream-json --verbose \
  "${extra[@]}" > "$out/engine-execution.jsonl"
