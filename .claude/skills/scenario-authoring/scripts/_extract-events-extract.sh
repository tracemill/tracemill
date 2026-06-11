#!/usr/bin/env bash
# _extract-events-extract.sh <dataset> <format> <key> <value> <out-file>
#
# Writes the first event whose <key> equals <value> to <out-file>. Emits
# JSON {sample_path}.
set -euo pipefail
DATASET="$1"; FORMAT="$2"; KEY="$3"; VALUE="$4"; OUT="$5"

case "$FORMAT" in
  xml)
    # yq (Mike Farah, Go) has no --arg flag — that's a jq feature. Convert
    # XML → JSON via yq, select in jq, then round-trip back to XML via yq.
    # `if length == 0 then empty else ...` produces no output on no-match so
    # the empty-file guard below fires; otherwise `.[0] | {Event: .}` gets
    # re-emitted as XML.
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
    # Dotted-path fallback so nested keys (e.g. userIdentity.userName) work
    # the same as top-level keys. `if length == 0 then empty else .[0] end`
    # emits no output on no-match so the empty-file guard fires; without it,
    # `.[0]` would write literal `null`, slipping past the check.
    jq --arg key "$KEY" --arg val "$VALUE" '
        (if type == "array" then . elif has("Records") then .Records else [.] end)
        | map(select(
            ((.[$key]) // (reduce ($key | split(".")[]) as $p (.; if type == "object" then .[$p] else empty end))) | tostring == $val
          ))
        | if length == 0 then empty else .[0] end' "$DATASET" > "$OUT"
    ;;
  ndjson)
    # Truncate $OUT up-front so stale content from a prior run can't slip
    # past the empty-file guard below when the current invocation finds no
    # match. (The xml/json/kv/text branches redirect with `>` at their
    # single command, which truncates atomically; the ndjson branch's
    # conditional `printf > "$OUT"` inside the loop would otherwise leave
    # any pre-existing file untouched on no-match.)
    : > "$OUT"
    # Scan line by line so nested-key matches work. Write the first line
    # whose $KEY value equals $VALUE.
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
    # First line whose $KEY=value field equals $VALUE.
    # Splits on runs of '=' / space / tab via split(..., /[=[:space:]]+/);
    # KEYs at odd indices, VALUEs at even. Plain `-F"[= ]"` would emit
    # an empty field for every extra delimiter (e.g. `a=1  b=2` with two
    # spaces), shifting indices and breaking the i+=2 pairing. sub()
    # strips any leading whitespace so a[1] isn't an empty leading field.
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
    # Text has no structured fields — only the "all" pseudo-group from
    # summary. Extract the first non-empty line when VALUE is "all"; any
    # other value has nothing to match, so the empty-file guard fires.
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
