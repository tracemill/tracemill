#!/usr/bin/env bash
# _extract-events-summary.sh <dataset> <format> <key>
#
# Called by extract-events.sh. Emits: {format, total, key, groups: [...]}
set -euo pipefail
DATASET="$1"; FORMAT="$2"; KEY="$3"

[[ -n "$KEY" ]] || { echo '_extract-events-summary: --key required' >&2; exit 2; }

groups_json=""
total=0

case "$FORMAT" in
  xml)
    # yq -p xml loads into an object. The primary count uses a recursive
    # descent that finds maps shaped like Windows events (have "System" or
    # "EventData") regardless of whether they sit under an <Events>
    # wrapper — so wrapper-less single events are handled by this path
    # too.
    total="$(yq -p xml -o json '([.. | select(tag == "!!map") | select(has("System") or has("EventData"))] | length)' "$DATASET")"
    if [[ "$total" == "0" || -z "$total" ]]; then
      # Defensive fallback for the wrapped <Events><Event>...</Event></Events>
      # shape when the events don't carry System/EventData (e.g. custom
      # provider XML that the recursive descent above doesn't recognise).
      # Note: this fallback DOES require the <Events> wrapper.
      total="$(yq -p xml -o json '[.Events.Event] | flatten | length' "$DATASET" 2>/dev/null || echo 0)"
    fi
    # Emit groups via a jq pipeline over the yq-to-json conversion.
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
    # Array-of-objects, or {Records: [...]}, or single object. Normalise.
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
    # Filter blank lines so total matches what samples/extract see (they
    # use `awk 'NF > 0'`). Dotted-path fallback mirrors the json branch
    # above so nested keys like userIdentity.userName work consistently
    # across all three modes for NDJSON.
    total="$(awk 'NF > 0' "$DATASET" | wc -l | tr -d ' ')"
    groups_json="$(awk 'NF > 0' "$DATASET" | jq --slurp --arg key "$KEY" '
        map(.[$key] // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end)))
        | map(tostring)
        | group_by(.)
        | map({key: .[0], count: length})')"
    ;;
  kv)
    # Filter blank lines so total matches what samples/extract see (they
    # use `[[ -z "$val" ]] && continue`, effectively skipping NF==0 lines).
    # Matches the ndjson branch's semantics: total == sum of group counts.
    total="$(awk 'NF > 0' "$DATASET" | wc -l | tr -d ' ')"
    # Build groups via jq so key values containing JSON-significant chars
    # (`"`, `\`, control bytes) are properly escaped. The pipeline:
    #   1. awk 'NF > 0'           — drop blank lines
    #   2. awk … print $(i+1)      — emit one raw value per line, stopping
    #                                at the first matching key so each event
    #                                contributes at most once (matches the
    #                                samples/extract handlers which use
    #                                `next`/`exit`; without `break` a line
    #                                like `EventCode=A EventCode=B` would
    #                                inflate group counts past `total`).
    #   3. sort | uniq -c          — count per distinct value (`   N value`)
    #   4. jq -Rsc                 — slurp as a single string, split on \n,
    #                                drop empties, parse each "<count> <value>"
    #                                line into {key,count}; jq handles the
    #                                JSON encoding of arbitrary values safely.
    groups_json="$(awk 'NF > 0' "$DATASET" | awk -v key="$KEY" '
        # Split each line on runs of `=`, space, or tab. Plain `-F"[= ]"`
        # would emit an empty field for every extra delimiter character
        # (e.g. `a=1  b=2` with two spaces), shifting every subsequent
        # field and breaking the odd-index/even-index key/value pairing.
        # Using `split($0, a, /[=[:space:]]+/)` collapses adjacent
        # delimiters into one. Leading whitespace would still make a[1]
        # empty (regex FS does not skip leading delimiters the way the
        # default whitespace FS does), so sub() strips it first.
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
    # Same blank-line filter as kv so 'all' count matches the file's real
    # event count and (for samples/extract) what the 'first non-empty
    # line' rule picks. Build the single-group JSON via jq for consistency
    # with the other branches (defensive — $total is numeric so direct
    # interpolation would also work, but routing through jq removes a
    # whole class of "what if this value contains a quote" concerns from
    # future maintainers' minds).
    total="$(awk 'NF > 0' "$DATASET" | wc -l | tr -d ' ')"
    groups_json="$(jq -nc --argjson count "$total" '[{key: "all", count: $count}]')"
    ;;
  *) echo "_extract-events-summary: unsupported format: $FORMAT" >&2; exit 2 ;;
esac

jq -n --arg format "$FORMAT" --argjson total "$total" --arg key "$KEY" --argjson groups "$groups_json" \
  '{format: $format, total: $total, key: $key, groups: $groups}'
