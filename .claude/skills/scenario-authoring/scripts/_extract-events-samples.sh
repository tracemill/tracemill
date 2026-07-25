#!/usr/bin/env bash
# _extract-events-samples.sh <dataset> <format> <key> <out-dir>
# Dispatched by extract-events.sh for mode=samples. Writes one event per distinct key value; emits JSON [{key, sample_path}, ...].
set -euo pipefail
DATASET="$1"; FORMAT="$2"; KEY="$3"; OUT="$4"

[[ -n "$KEY" ]] || { echo '_extract-events-samples: --key required' >&2; exit 2; }
mkdir -p "$OUT"

# Produces a filesystem-safe filename from an arbitrary key value.
# Appends a cksum-hex suffix whenever sanitisation changes the raw key or the stem
# exceeds $max_stem bytes, so two keys that collapse to the same sanitised string
# still get distinct filenames.
safe_key() {
  local raw="$1" safe hash stem max_stem
  max_stem=200
  safe="$(printf '%s' "$raw" | tr -c 'A-Za-z0-9._-' '_')"
  if [[ "$safe" == "$raw" && ${#safe} -le $max_stem ]]; then
    printf '%s' "$safe"
  else
    hash="$(printf '%x' "$(printf '%s' "$raw" | cksum | awk '{print $1}')")"
    stem="$safe"
    # Reserve room for the "-<hash>" suffix (CRC32 = 1-8 hex chars).
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
    # yq has no --arg; convert once to JSON, select in jq, round-trip back to XML.
    json_all="$(yq -p xml -o json '.' "$DATASET")"
    keys="$(jq -r --arg key "$KEY" '
        [.. | objects | select(has("System") or has("EventData"))]
        | map(
            [($key | split("/"))[]] as $path
            | reduce $path[] as $p (.; if type == "object" then .[$p] else empty end)
          )
        | map(tostring) | unique | .[]' <<< "$json_all")"
    # `while IFS= read -r` instead of `for k in $keys` preserves whitespace in values.
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
    # Process substitution instead of pipe so mutations to $results survive the loop (pipe runs a subshell).
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
    # Two-pass: collect distinct values first, then awk-scan once per value.
    # Avoids `declare -A` (requires Bash 4+; macOS ships Bash 3.2).
    # split(..., /[=[:space:]]+/) collapses adjacent delimiters so indices
    # stay consistent; sub() strips leading whitespace for the same reason.
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
  admon)
    ext="log"
    records="$(jq -Rn -f "$(dirname "${BASH_SOURCE[0]}")/admon-records.jq" "$DATASET")"
    keys="$(jq -r --arg key "$KEY" '[.[].fields[$key] | select(. != null) | tostring] | unique[]' <<< "$records")"
    while IFS= read -r val; do
      [[ -z "$val" ]] && continue
      safe="$(safe_key "$val")"
      out="$OUT/$safe.$ext"
      jq -j --arg key "$KEY" --arg val "$val" '
        [.[] | select((.fields[$key] | tostring) == $val)][0].raw // empty
      ' <<< "$records" > "$out"
      results="$(jq -c --arg key "$val" --arg path "$out" '. + [{key: $key, sample_path: $path}]' <<< "$results")"
    done <<< "$keys"
    ;;
  text)
    ext="log"
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
