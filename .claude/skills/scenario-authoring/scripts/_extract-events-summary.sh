#!/usr/bin/env bash
# _extract-events-summary.sh <dataset> <format> <key>
# Dispatched by extract-events.sh for mode=summary. Emits JSON {format, total, key, groups: [{key, count}, ...]}.
set -euo pipefail
DATASET="$1"; FORMAT="$2"; KEY="$3"

[[ -n "$KEY" ]] || { echo '_extract-events-summary: --key required' >&2; exit 2; }

groups_json=""
total=0

case "$FORMAT" in
  xml)
    total="$(yq -p xml -o json '([.. | select(tag == "!!map") | select(has("System") or has("EventData"))] | length)' "$DATASET")"
    if [[ "$total" == "0" || -z "$total" ]]; then
      # Fallback for wrapped <Events><Event>...</Event></Events> shapes without System/EventData.
      total="$(yq -p xml -o json '[.Events.Event] | flatten | length' "$DATASET" 2>/dev/null || echo 0)"
    fi
    groups_json="$(yq -p xml -o json "." "$DATASET" \
      | jq --arg key "$KEY" '
          def walk_events:
            [.. | objects | select(has("System") or has("EventData"))];
          walk_events
          | map(
              [($key | split("/"))[]] as $path
              | reduce $path[] as $p (.; if type == "object" then .[$p] else empty end)
            )
          | map(tostring)
          | group_by(.)
          | map({key: .[0], count: length})
        ')"
    ;;
  json)
    total="$(jq '
        if type == "array" then length
        elif has("Records") then (.Records | length)
        else 1 end' "$DATASET")"
    groups_json="$(jq --arg key "$KEY" '
        (if type == "array" then .
         elif has("Records") then .Records
         else [.] end)
        | map(.[$key] // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end)))
        | map(tostring)
        | group_by(.)
        | map({key: .[0], count: length})' "$DATASET")"
    ;;
  ndjson)
    # `awk 'NF > 0'` filters blank lines so total matches what samples/extract see.
    total="$(awk 'NF > 0' "$DATASET" | wc -l | tr -d ' ')"
    groups_json="$(awk 'NF > 0' "$DATASET" | jq --slurp --arg key "$KEY" '
        map(.[$key] // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end)))
        | map(tostring)
        | group_by(.)
        | map({key: .[0], count: length})')"
    ;;
  kv)
    total="$(awk 'NF > 0' "$DATASET" | wc -l | tr -d ' ')"
    # split(..., /[=[:space:]]+/) collapses adjacent delimiters; sub() strips leading whitespace
    # so a[1] is never an empty leading field. Routes through jq to safely encode arbitrary values.
    groups_json="$(awk 'NF > 0' "$DATASET" | awk -v key="$KEY" '
        {
          line = $0
          sub(/^[[:space:]]+/, "", line)
          n = split(line, a, /[=[:space:]]+/)
          for (i=1; i<=n; i+=2) {
            if (a[i]==key) { print a[i+1]; break }
          }
        }
      ' | sort | uniq -c | jq -Rsc '
        split("\n")
        | map(select(length > 0))
        | map(capture("^\\s*(?<count>[0-9]+)\\s+(?<key>.*)$"))
        | map({key: .key, count: (.count | tonumber)})')"
    ;;
  text)
    total="$(awk 'NF > 0' "$DATASET" | wc -l | tr -d ' ')"
    groups_json="$(jq -nc --argjson count "$total" '[{key: "all", count: $count}]')"
    ;;
  *) echo "_extract-events-summary: unsupported format: $FORMAT" >&2; exit 2 ;;
esac

jq -n --arg format "$FORMAT" --argjson total "$total" --arg key "$KEY" --argjson groups "$groups_json" \
  '{format: $format, total: $total, key: $key, groups: $groups}'
