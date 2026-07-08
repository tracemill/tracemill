#!/usr/bin/env bash
# Emit a unified textual diff of a master event against a generated event, after
# canonicalizing each side's formatting (indentation, key/whitespace layout) so
# the diff surfaces value differences rather than layout noise. Every remaining
# difference is shown flat and unsuppressed -- including the environmental fields
# (gen.* timestamps, GUIDs, request IDs, IPs) that differ on every render by
# design. This is a human-facing report aid; the pass/warn/fail fidelity verdict
# is compare-fidelity.sh's job, not this script's.
#
# Only the FIRST event of each side is diffed: the master is a single promoted
# sample, and a multi-emit scenario renders a burst whose first event is the
# representative one (mirrors compare-fidelity.sh's first-record coverage rule).
#
# Internal to the scenario-authoring skill; not a stable CLI.
set -euo pipefail

for cmd in yq jq diff awk grep head sed mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "diff-against-master.sh: required command '$cmd' not found in PATH" >&2
    exit 127
  }
done

MASTER=""
GENERATED=""
FORMAT="auto"

require_flag_value() {
  local flag="$1" next="${2-}"
  if [[ -z "$next" || "$next" == --* ]]; then
    echo "diff-against-master.sh: $flag requires a value" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master)    require_flag_value "$1" "${2-}"; MASTER="$2";    shift 2 ;;
    --generated) require_flag_value "$1" "${2-}"; GENERATED="$2"; shift 2 ;;
    --format)    require_flag_value "$1" "${2-}"; FORMAT="$2";    shift 2 ;;
    *) echo "diff-against-master.sh: unknown flag: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$MASTER"    ]] || { echo "diff-against-master.sh: --master required"    >&2; exit 2; }
[[ -n "$GENERATED" ]] || { echo "diff-against-master.sh: --generated required" >&2; exit 2; }
[[ -f "$MASTER"    ]] || { echo "diff-against-master.sh: master not found: $MASTER"       >&2; exit 2; }
[[ -f "$GENERATED" ]] || { echo "diff-against-master.sh: generated not found: $GENERATED" >&2; exit 2; }

case "$FORMAT" in
  auto|xml|json) ;;
  *) echo "diff-against-master.sh: unsupported format: $FORMAT (expected auto|xml|json)" >&2; exit 2 ;;
esac

# First non-blank byte '<' => XML, else JSON. Same heuristic as compare-fidelity.sh
# so the two scripts always agree on a file's surface.
detect_format() {
  local f="$1" head_bytes head_trimmed
  head_bytes="$(head -c 200 "$f" 2>/dev/null || true)"
  head_trimmed="$(printf '%s' "$head_bytes" | sed -E $'s/^(\xef\xbb\xbf|[[:space:]])+//')"
  if [[ "$head_trimmed" == "<"* ]]; then echo "xml"; else echo "json"; fi
}

# Canonicalize one JSON/NDJSON event: select the first record (bare object, array
# element, Records[0], or first NDJSON line -- mirrors compare-fidelity.sh) and
# re-emit it pretty-printed with sorted keys, so key ordering never shows as diff
# noise.
canon_json() {
  local f="$1" out
  out="$(jq -nS '
      [limit(2; inputs)] as $docs
      | if ($docs | length) == 0 then error("no JSON values")
        else
          ($docs[0]) as $first
          | if ($first | type) == "array" then $first[0]
            elif ($first | type) == "object"
                 and ($first | has("Records"))
                 and (($first.Records | type) == "array")
              then $first.Records[0]
            else $first
            end
        end
    ' "$f" 2>/dev/null)" || {
    echo "diff-against-master.sh: cannot parse JSON/NDJSON from $f" >&2
    return 1
  }
  printf '%s' "$out" | jq -e 'type == "object" and (length > 0)' >/dev/null 2>&1 || {
    echo "diff-against-master.sh: $f did not yield a non-empty event object" >&2
    return 1
  }
  printf '%s\n' "$out"
}

# Canonicalize one XML event: take the first <Event>...</Event> (a scenario with
# multiple emit steps renders sibling <Event> roots that no single-document XML
# parser accepts) and re-emit it through yq's XML pretty-printer. yq is applied to
# both sides, so its formatting quirks are symmetric and never produce a spurious
# diff (e.g. <X/> normalizes to <X></X>). Note yq also normalizes entity encoding
# -- a literal > and &gt; both re-emit as &gt; -- so this diff does NOT surface
# raw-byte entity drift; that is compare-fidelity.sh's raw_encoding_drift check
# (step 10), not this informational aid.
canon_xml() {
  local f="$1" src out
  if grep -q '</Event>' "$f"; then
    src="$(awk 'BEGIN{RS="</Event>"} NR==1{printf "%s</Event>", $0; exit}' "$f")"
  else
    src="$(cat "$f")"
  fi
  # Strip the optional <?xml ...?> declaration: a captured master often omits it
  # while an engine render emits one (and a burst carries one per event), and yq
  # passes it through verbatim -- so its presence/absence would show as diff noise.
  src="$(printf '%s' "$src" | sed -E 's/<\?xml[^>]*>//g')"
  out="$(printf '%s' "$src" | yq -p xml -o xml '.' 2>/dev/null)" || {
    echo "diff-against-master.sh: cannot parse XML from $f" >&2
    return 1
  }
  printf '%s\n' "$out"
}

canon() {
  local f="$1" fmt="$2"
  case "$fmt" in
    xml)  canon_xml  "$f" ;;
    json) canon_json "$f" ;;
    *) echo "diff-against-master.sh: unsupported format: $fmt" >&2; return 2 ;;
  esac
}

# Count events in the generated render so a burst can be flagged (only the first
# is diffed). Best-effort: any parse hiccup falls back to 1, since this is only an
# informational note. The JSON count reads the first value to pick the shape and
# then reduces the rest, so an NDJSON burst is never slurped into memory (same
# no-buffering discipline as compare-fidelity.sh's flatten_json).
generated_event_count() {
  local f="$1" fmt="$2" n
  case "$fmt" in
    xml)  n="$(awk 'BEGIN{RS="</Event>"} END{print (NR ? NR-1 : 0)}' "$f" 2>/dev/null || true)" ;;
    json) n="$(jq -n '
             (input) as $first
             | if ($first | type) == "array" then ($first | length)
               elif ($first | type) == "object"
                    and ($first | has("Records"))
                    and (($first.Records | type) == "array")
                 then ($first.Records | length)
               else 1 + (reduce inputs as $_ (0; . + 1))
               end' "$f" 2>/dev/null || true)" ;;
  esac
  [[ "$n" =~ ^[0-9]+$ ]] || n=1
  echo "$n"
}

m_format="$FORMAT"
g_format="$FORMAT"
if [[ "$FORMAT" == "auto" ]]; then
  m_format="$(detect_format "$MASTER")"
  g_format="$(detect_format "$GENERATED")"
  # XML master vs JSON generated almost always means wrong file paths; hard-fail
  # rather than diff two unrelated shapes (same guard as compare-fidelity.sh).
  if [[ "$m_format" != "$g_format" ]]; then
    echo "diff-against-master.sh: master format ($m_format, $MASTER) and generated format ($g_format, $GENERATED) differ -- pass --format to override or check the file paths" >&2
    exit 2
  fi
fi

# macOS/BSD mktemp requires an explicit -t template; the bare form fails there.
m_canon="$(mktemp -t diff-against-master.XXXXXX)"
g_canon="$(mktemp -t diff-against-master.XXXXXX)"
trap 'rm -f "$m_canon" "$g_canon"' EXIT

canon "$MASTER"    "$m_format" > "$m_canon"
canon "$GENERATED" "$g_format" > "$g_canon"

gen_count="$(generated_event_count "$GENERATED" "$g_format")"
if [[ "$gen_count" -gt 1 ]]; then
  echo "# generated render produced $gen_count events; diffing the first against the master"
fi

# diff exits 0 (identical) or 1 (differences) -- both are success here; only >1 is
# a real tool error. Differences (notably gen.* churn) are expected, not a defect.
set +e
diff -u --label "master:    $MASTER" --label "generated: $GENERATED" "$m_canon" "$g_canon"
rc=$?
set -e
if [[ "$rc" -gt 1 ]]; then
  echo "diff-against-master.sh: diff failed (exit $rc)" >&2
  exit "$rc"
fi
if [[ "$rc" -eq 0 ]]; then
  echo "# no differences after formatting canonicalization"
fi
exit 0
