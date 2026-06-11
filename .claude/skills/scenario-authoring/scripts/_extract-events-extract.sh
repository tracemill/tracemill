#!/usr/bin/env bash
# _extract-events-extract.sh <dataset> <format> <key> <value> <out-file>
# Dispatched by extract-events.sh for mode=extract. Writes first matching event; emits JSON {sample_path}.
set -euo pipefail
DATASET="$1"; FORMAT="$2"; KEY="$3"; VALUE="$4"; OUT="$5"

case "$FORMAT" in
  xml)
    # yq has no --arg; convert XML→JSON via yq, select in jq, round-trip back to XML.
    yq -p xml -o json '.' "$DATASET" \
      | jq --arg key "$KEY" --arg val "$VALUE" '
          [.. | objects | select(has("System") or has("EventData"))]
          | map(select(
              ([($key | split("/"))[]] as $path | reduce $path[] as $p (.; if type == "object" then .[$p] else empty end) | tostring) == $val
            ))
          | if length == 0 then empty else .[0] | {Event: .} end' \
      | yq -p json -o xml '.' > "$OUT"
    ;;
  json)
    jq --arg key "$KEY" --arg val "$VALUE" '
        (if type == "array" then . elif has("Records") then .Records else [.] end)
        | map(select(
            ((.[$key]) // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end))) | tostring == $val
          ))
        | if length == 0 then empty else .[0] end' "$DATASET" > "$OUT"
    ;;
  ndjson)
    # Truncate up-front so a prior run's content can't slip past the empty-file guard on no-match.
    : > "$OUT"
    while IFS= read -r line; do
      v="$(jq -r --arg key "$KEY" '
          (.[$key] // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end)))
          // "" | tostring' <<< "$line" 2>/dev/null || echo "")"
      if [[ "$v" == "$VALUE" ]]; then
        printf '%s\n' "$line" > "$OUT"
        break
      fi
    done < <(awk 'NF > 0' "$DATASET")
    ;;
  kv)
    awk -v key="$KEY" -v val="$VALUE" '
      {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        n = split(line, a, /[=[:space:]]+/)
        for (i=1; i<=n; i+=2) if (a[i]==key && a[i+1]==val) { print; exit 0 }
      }
    ' "$DATASET" > "$OUT"
    ;;
  text)
    if [[ "$VALUE" == "all" ]]; then
      awk 'NF > 0 {print; exit}' "$DATASET" > "$OUT"
    else
      : > "$OUT"
    fi
    ;;
  *) echo "_extract-events-extract: format $FORMAT not supported" >&2; exit 2 ;;
esac

if [[ ! -s "$OUT" ]]; then
  echo "_extract-events-extract: no event matched $KEY=$VALUE" >&2
  exit 1
fi

jq -n --arg path "$OUT" '{sample_path: $path}'
