#!/usr/bin/env bash
# extract-events.sh --dataset <path> --key <field> --mode <summary|samples|extract> [--format <fmt>] [--value <v>] [--out <path>]
# Internal helper for the scenario-authoring skill; not a stable CLI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/admon-support.sh"

for cmd in jq yq awk sed head grep wc tr sort uniq cksum mkdir; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "extract-events.sh: required command '$cmd' not found in PATH" >&2
    exit 127
  }
done

DATASET=""
FORMAT="auto"
KEY=""
MODE=""
VALUE=""
OUT=""

require_flag_value() {
  local flag="$1" next="${2-}"
  if [[ -z "$next" || "$next" == --* ]]; then
    echo "extract-events.sh: $flag requires a value" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dataset) require_flag_value "$1" "${2-}"; DATASET="$2"; shift 2 ;;
    --format)  require_flag_value "$1" "${2-}"; FORMAT="$2";  shift 2 ;;
    --key)     require_flag_value "$1" "${2-}"; KEY="$2";     shift 2 ;;
    --mode)    require_flag_value "$1" "${2-}"; MODE="$2";    shift 2 ;;
    --value)   require_flag_value "$1" "${2-}"; VALUE="$2";   shift 2 ;;
    --out)     require_flag_value "$1" "${2-}"; OUT="$2";     shift 2 ;;
    *) echo "extract-events.sh: unknown flag: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$DATASET" ]] || { echo "extract-events.sh: --dataset required" >&2; exit 2; }
[[ -n "$MODE" ]]    || { echo "extract-events.sh: --mode required" >&2; exit 2; }
[[ -f "$DATASET" ]] || { echo "extract-events.sh: dataset not found: $DATASET" >&2; exit 2; }

# Count top-level JSON values capped at 2; used to distinguish a single JSON doc from NDJSON
# without slurping a potentially large file. Returns "" on non-JSON input.
json_value_count() {
  jq -n 'reduce limit(2; inputs) as $_ (0; . + 1)' "$1" 2>/dev/null || echo ""
}

detect_format() {
  local f="$1"

  local n
  n="$(json_value_count "$f")"
  if [[ "$n" == "1" ]]; then
    echo "json"; return
  elif [[ "$n" =~ ^[0-9]+$ && "$n" -gt 1 ]]; then
    echo "ndjson"; return
  fi

  local head_bytes head_trimmed
  head_bytes="$(head -c 200 "$f" 2>/dev/null || true)"
  head_trimmed="$(printf '%s' "$head_bytes" | sed -E $'s/^(\xef\xbb\xbf|[[:space:]])+//')"

  if [[ "$head_trimmed" == "<"* ]]; then echo "xml"; return; fi
  if admon_probe_file "$f"; then
    echo "admon"; return
  fi
  if awk 'NF > 0 {print; exit}' "$f" | grep -qE '[A-Za-z_]+='; then
    echo "kv"; return
  fi
  echo "text"
}

if [[ "$FORMAT" == "auto" ]]; then
  FORMAT="$(detect_format "$DATASET")"
fi

# Reclassify json→ndjson when the bytes are actually NDJSON so the per-mode
# handlers receive the correct format even when the caller passes --format json.
if [[ "$FORMAT" == "json" ]]; then
  n="$(json_value_count "$DATASET")"
  if [[ "$n" =~ ^[0-9]+$ && "$n" -gt 1 ]]; then
    FORMAT="ndjson"
  fi
fi

[[ -n "$KEY" ]] || { echo "extract-events.sh: --key required" >&2; exit 2; }

case "$MODE" in
  summary)
    exec "$SCRIPT_DIR/_extract-events-summary.sh" "$DATASET" "$FORMAT" "$KEY" ;;
  samples)
    [[ -n "$OUT" ]] || { echo "extract-events.sh: --out required for samples mode" >&2; exit 2; }
    mkdir -p "$OUT"
    exec "$SCRIPT_DIR/_extract-events-samples.sh" "$DATASET" "$FORMAT" "$KEY" "$OUT" ;;
  extract)
    [[ -n "$OUT" ]] || { echo "extract-events.sh: --out required for extract mode" >&2; exit 2; }
    [[ -n "$VALUE" ]] || { echo "extract-events.sh: --value required for extract mode" >&2; exit 2; }
    exec "$SCRIPT_DIR/_extract-events-extract.sh" "$DATASET" "$FORMAT" "$KEY" "$VALUE" "$OUT" ;;
  *) echo "extract-events.sh: unknown mode: $MODE" >&2; exit 2 ;;
esac
