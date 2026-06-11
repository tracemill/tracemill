#!/usr/bin/env bash
# _extract-events-samples.sh <dataset> <format> <key> <out-dir>
#
# Writes one representative event per distinct key value to <out-dir>/<key>.<ext>
# and emits JSON [{key, sample_path}, ...].
set -euo pipefail
DATASET="$1"; FORMAT="$2"; KEY="$3"; OUT="$4"

[[ -n "$KEY" ]] || { echo '_extract-events-samples: --key required' >&2; exit 2; }
mkdir -p "$OUT"

# Build a filesystem-safe filename from an arbitrary key value.
#
#   • If the raw key already consists only of [A-Za-z0-9._-] characters and
#     fits within $max_stem bytes, the sanitiser is a no-op and the filename
#     stays human-readable for common cases (`10`, `DeleteTrail`).
#   • If sanitisation changes the key, a short cksum-hex suffix is appended
#     so two different raw keys that would collapse to the same sanitised
#     name (e.g. `a/b` and `a?b` both → `a_b`) get distinct filenames
#     (`a_b-<hash1>`, `a_b-<hash2>`). Without the suffix the second sample
#     would overwrite the first (xml/json branches) or be silently skipped
#     by the `[[ ! -f "$out" ]]` guard (ndjson branch).
#   • If the sanitised stem exceeds $max_stem bytes (e.g. raw key is a long
#     command line of all-safe chars), it is truncated and a cksum-hex
#     suffix is always appended so two different long stems that share a
#     prefix still get distinct filenames. Without truncation, samples
#     whose key value approaches NAME_MAX (255 on most filesystems) would
#     fail at `> "$out"` time.
#
# `printf '%s'` (not `echo`) drops the trailing newline that `tr` would
# otherwise turn into a trailing `_`. `cksum` is POSIX-mandatory; output
# is decimal CRC32 + byte count, so we extract field 1 and reformat as
# hex.
safe_key() {
  local raw="$1" safe hash stem max_stem
  max_stem=200
  safe="$(printf '%s' "$raw" | tr -c 'A-Za-z0-9._-' '_')"
  if [[ "$safe" == "$raw" && ${#safe} -le $max_stem ]]; then
    printf '%s' "$safe"
  else
    hash="$(printf '%x' "$(printf '%s' "$raw" | cksum | awk '{print $1}')")"
    stem="$safe"
    # Reserve room for the "-<hash>" suffix when truncating. The hash is
    # 1-8 hex chars (CRC32 fits in 32 bits), so this caps the final name
    # at $max_stem bytes total.
    if [[ ${#stem} -gt $((max_stem - 1 - ${#hash})) ]]; then
      stem="${stem:0:$((max_stem - 1 - ${#hash}))}"
    fi
    printf '%s-%s' "$stem" "$hash"
  fi
}

results="[]"

case "$FORMAT" in
  xml)
    ext="xml"
    # yq (Mike Farah, Go) has no --arg flag — that's a jq feature. Convert
    # XML → JSON via yq once, select in jq, round-trip selected event back
    # to XML with a {Event: .} wrap so output root is <Event>.
    json_all="$(yq -p xml -o json '.' "$DATASET")"
    keys="$(jq -r --arg key "$KEY" '
        [.. | objects | select(has("System") or has("EventData"))]
        | map(
            [($key | split("/"))[]] as $path
            | reduce $path[] as $p (.; if type == "object" then .[$p] else empty end)
          )
        | map(tostring) | unique | .[]' <<< "$json_all")"
    # `while IFS= read -r` instead of `for k in $keys` so values containing
    # whitespace are treated as a single key (matches the json branch).
    while IFS= read -r k; do
      [[ -z "$k" ]] && continue
      safe="$(safe_key "$k")"
      out="$OUT/$safe.$ext"
      jq --arg key "$KEY" --arg val "$k" '
          [.. | objects | select(has("System") or has("EventData"))]
          | map(select(
              ([($key | split("/"))[]] as $path | reduce $path[] as $p (.; if type == "object" then .[$p] else empty end) | tostring) == $val
            ))
          | .[0]
          | {Event: .}
        ' <<< "$json_all" | yq -p json -o xml '.' > "$out"
      results="$(jq -c --arg key "$k" --arg path "$out" '. + [{key: $key, sample_path: $path}]' <<< "$results")"
    done <<< "$keys"
    ;;
  json)
    ext="json"
    # Use split('.') with a reduce fallback so nested keys like
    # "userIdentity.userName" work the same as top-level keys. Matches
    # the summary-mode handler's semantics.
    keys="$(jq -r --arg key "$KEY" '
        (if type == "array" then . elif has("Records") then .Records else [.] end)
        | map(.[$key] // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end)))
        | map(tostring) | unique | .[]' "$DATASET")"
    while IFS= read -r k; do
      [[ -z "$k" ]] && continue
      safe="$(safe_key "$k")"
      out="$OUT/$safe.$ext"
      jq --arg key "$KEY" --arg val "$k" '
          (if type == "array" then . elif has("Records") then .Records else [.] end)
          | map(select(
              ((.[$key]) // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end))) | tostring == $val
            ))
          | .[0]' "$DATASET" > "$out"
      results="$(jq -c --arg key "$k" --arg path "$out" '. + [{key: $key, sample_path: $path}]' <<< "$results")"
    done <<< "$keys"
    ;;
  ndjson)
    ext="ndjson"
    # Read via process substitution so mutations to $results persist (pipe
    # into `while` would run the loop in a subshell and lose the variable).
    # Dotted-path fallback mirrors the json branch.
    while IFS= read -r line; do
      val="$(jq -r --arg key "$KEY" '
          (.[$key] // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end)))
          // "" | tostring' <<< "$line" 2>/dev/null || echo "")"
      [[ -z "$val" ]] && continue
      safe="$(safe_key "$val")"
      out="$OUT/$safe.$ext"
      if [[ ! -f "$out" ]]; then
        echo "$line" > "$out"
        results="$(jq -c --arg key "$val" --arg path "$out" '. + [{key: $key, sample_path: $path}]' <<< "$results")"
      fi
    done < <(awk 'NF > 0' "$DATASET")
    ;;
  kv)
    ext="log"
    # Group key=value lines by value of $KEY; write the first line per
    # distinct value. Two-pass design avoids `declare -A` (which requires
    # Bash 4+; macOS still ships /usr/bin/bash 3.2):
    #   1. sort -u to get the distinct values once
    #   2. per distinct value, awk-scan once for the first matching line
    # Splits on runs of '=' / space / tab via split(..., /[=[:space:]]+/);
    # KEYs at odd indices, VALUEs at even. Plain `-F"[= ]"` would emit an
    # empty field for every extra delimiter (e.g. `a=1  b=2` with two
    # spaces), shifting indices and breaking the i+=2 pairing. sub()
    # strips any leading whitespace so a[1] isn't an empty leading field.
    distinct_vals="$(awk -v key="$KEY" '
        {
          line = $0
          sub(/^[[:space:]]+/, "", line)
          n = split(line, a, /[=[:space:]]+/)
          for (i=1; i<=n; i+=2) if (a[i]==key) { print a[i+1]; next }
        }
      ' "$DATASET" | sort -u)"
    while IFS= read -r val; do
      [[ -z "$val" ]] && continue
      first_line="$(awk -v key="$KEY" -v target="$val" '
          {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            n = split(line, a, /[=[:space:]]+/)
            for (i=1; i<=n; i+=2) if (a[i]==key && a[i+1]==target) { print; exit }
          }
        ' "$DATASET")"
      [[ -z "$first_line" ]] && continue
      safe="$(safe_key "$val")"
      out="$OUT/$safe.$ext"
      printf '%s\n' "$first_line" > "$out"
      results="$(jq -c --arg key "$val" --arg path "$out" '. + [{key: $key, sample_path: $path}]' <<< "$results")"
    done <<< "$distinct_vals"
    ;;
  text)
    ext="log"
    # Summary reports a single "all" group; sample is the first non-empty
    # line of the file. The user-supplied $KEY is ignored (text has no
    # structured fields to group on).
    first_line="$(awk 'NF > 0 {print; exit}' "$DATASET")"
    if [[ -n "$first_line" ]]; then
      out="$OUT/all.$ext"
      printf '%s\n' "$first_line" > "$out"
      results="$(jq -c --arg key "all" --arg path "$out" '. + [{key: $key, sample_path: $path}]' <<< "$results")"
    fi
    ;;
  *)
    echo "_extract-events-samples: unsupported format: $FORMAT" >&2
    exit 2
    ;;
esac

echo "$results"
