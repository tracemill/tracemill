#!/usr/bin/env bash
# extract-events.sh --dataset <path> --key <field-path> --mode <summary|samples|extract>
#                  [--format <fmt>] [--value <v>] [--out <path-or-dir>]
#
# --format defaults to `auto` (detected from the file's first non-blank
# bytes — see detect_format below). Pass an explicit format to skip
# detection.
#
# Internal: implementation detail of the scenario-authoring skill
# (.claude/skills/scenario-authoring/SKILL.md). Not a stable CLI; flag names,
# output JSON shapes, and exit codes may change without notice.
#
# Three modes:
#   summary  → emits JSON {format, total, key, groups: [{key, count}, ...]}
#   samples  → writes one event per distinct key value to <out>/<key>.<ext>,
#              emits JSON [{key, sample_path}, ...]
#   extract  → writes the first event matching --key=--value to --out,
#              emits JSON {sample_path}
#
# Formats: auto | xml | json | ndjson | kv | text
#
# Deps: jq, yq (Mike Farah, Go), awk, sed.
set -euo pipefail

# Preflight: required commands. Fail early rather than letting set -e trip
# inside a dispatched handler (same pattern as resolve.sh / fetch-dataset.sh).
# `sed` is used by detect_format to strip leading BOM/whitespace before the
# prefix probes.
for cmd in jq yq awk sed head grep; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "extract-events.sh: required command '$cmd' not found in PATH" >&2
    exit 127
  }
done

# ── Flag parsing ──────────────────────────────────────────────────────────────
DATASET=""
FORMAT="auto"
KEY=""
MODE=""
VALUE=""
OUT=""

# Ensure the flag currently being parsed has a following value and that the
# value isn't another flag (e.g. `--dataset --mode foo` — user meant to
# pass a path but forgot). Without this guard, `set -u` would trip on the
# unset $2 and abort with a cryptic "unbound variable" instead of our
# intended usage/exit-2 diagnostic.
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

# ── Format detection ──────────────────────────────────────────────────────────

# Count top-level JSON values in $1, capped at 2 (so "2" means "two or more").
# Used to tell a single JSON document (count 1 — array, {Records:[…]}, or lone
# object, possibly pretty-printed) from NDJSON (count >1). `limit(2; inputs)`
# pulls at most the first two values from the lazy input stream and stops, so a
# multi-GB NDJSON file costs only its first two lines instead of a full slurp
# (the earlier `jq -s 'length'` parsed and held the entire file in memory).
# Tolerates a UTF-8 BOM / leading whitespace (jq skips both); prints "" when
# the input isn't parseable JSON so callers fall through to other formats.
json_value_count() {
  jq -n 'reduce limit(2; inputs) as $_ (0; . + 1)' "$1" 2>/dev/null || echo ""
}

detect_format() {
  local f="$1"

  # Try JSON/NDJSON first by counting top-level values (1 = single JSON doc,
  # possibly pretty-printed; >1 = NDJSON). This runs unconditionally so files
  # with a UTF-8 BOM or leading whitespace are still classified correctly;
  # jq fails fast on non-JSON input, so the fall-through cost is negligible.
  local n
  n="$(json_value_count "$f")"
  if [[ "$n" == "1" ]]; then
    echo "json"; return
  elif [[ "$n" =~ ^[0-9]+$ && "$n" -gt 1 ]]; then
    echo "ndjson"; return
  fi

  # Trim leading whitespace (incl. BOM) before the prefix probes so
  # XML/text/kv files with stray bytes are still classified correctly.
  local head_bytes head_trimmed
  head_bytes="$(head -c 200 "$f" 2>/dev/null || true)"
  head_trimmed="$(printf '%s' "$head_bytes" | sed -E $'s/^(\xef\xbb\xbf|[[:space:]])+//')"

  if [[ "$head_trimmed" == "<"* ]]; then echo "xml"; return; fi
  # Heuristic: if the first non-blank line has 'KEY=VALUE' tokens, call
  # it kv; otherwise plain text.
  if awk 'NF > 0 {print; exit}' "$f" | grep -qE '[A-Za-z_]+='; then
    echo "kv"; return
  fi
  echo "text"
}

if [[ "$FORMAT" == "auto" ]]; then
  FORMAT="$(detect_format "$DATASET")"
fi

# An explicit `--format json` on a file that is actually NDJSON (multiple
# top-level JSON values, e.g. a CloudTrail dataset with one event per line)
# would otherwise stream through the per-mode json handlers one value at a
# time: summary's `total`/`groups_json` become multi-value strings that
# trip the final `jq --argjson` ("invalid JSON text passed to --argjson"),
# and samples/extract silently mis-write. json and ndjson are two encodings
# of the same data, so reclassify json→ndjson when the bytes are NDJSON.
# This honours SKILL.md step 5 ("JSON-mode handles both shapes") and reuses
# the same bounded counter as `detect_format`'s `--format auto` path. Guarded
# on an unambiguous count > 1: a parse failure or a single document leaves
# FORMAT as json so the json handler still runs (and surfaces its own error
# for genuinely malformed input).
if [[ "$FORMAT" == "json" ]]; then
  n="$(json_value_count "$DATASET")"
  if [[ "$n" =~ ^[0-9]+$ && "$n" -gt 1 ]]; then
    FORMAT="ndjson"
  fi
fi

# ── Dispatch to per-mode handler ──────────────────────────────────────────────
# All three modes require --key (per-handler checks remain as defence in
# depth, but failing here gives a consistent error message at the dispatcher
# layer regardless of which handler the user reaches).
[[ -n "$KEY" ]] || { echo "extract-events.sh: --key required" >&2; exit 2; }

source_dir="$(dirname "${BASH_SOURCE[0]}")"
case "$MODE" in
  summary)
    exec "$source_dir/_extract-events-summary.sh" "$DATASET" "$FORMAT" "$KEY" ;;
  samples)
    [[ -n "$OUT" ]] || { echo "extract-events.sh: --out required for samples mode" >&2; exit 2; }
    mkdir -p "$OUT"
    exec "$source_dir/_extract-events-samples.sh" "$DATASET" "$FORMAT" "$KEY" "$OUT" ;;
  extract)
    [[ -n "$OUT" ]] || { echo "extract-events.sh: --out required for extract mode" >&2; exit 2; }
    [[ -n "$VALUE" ]] || { echo "extract-events.sh: --value required for extract mode" >&2; exit 2; }
    exec "$source_dir/_extract-events-extract.sh" "$DATASET" "$FORMAT" "$KEY" "$VALUE" "$OUT" ;;
  *) echo "extract-events.sh: unknown mode: $MODE" >&2; exit 2 ;;
esac
