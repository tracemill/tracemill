#!/usr/bin/env bash
# Parses a detection SPL string through Splunk's /services/search/parser REST
# endpoint, walks the command tree, and emits the final group-by tuple (one
# field per line). SPLUNK_URL and SPLUNK_AUTH are REQUIRED; no offline mode.
# Internal to the scenario-authoring skill; not a stable CLI.

set -euo pipefail

command -v curl >/dev/null 2>&1 || {
    echo "extract-spl-groupby.sh: required command 'curl' not found in PATH" >&2
    exit 127
}
command -v jq >/dev/null 2>&1 || {
    echo "extract-spl-groupby.sh: required command 'jq' not found in PATH" >&2
    exit 127
}

if [[ $# -ne 1 ]]; then
    echo "usage: $0 \"<spl>\"" >&2
    exit 2
fi

SPL="$1"

if [[ -z "${SPLUNK_URL:-}" ]]; then
    echo "extract-spl-groupby.sh: SPLUNK_URL not set (e.g. https://splunk.example.com:8089)" >&2
    exit 1
fi

if [[ -z "${SPLUNK_AUTH:-}" ]]; then
    if [[ -n "${SPLUNK_PASSWORD:-}" ]]; then
        SPLUNK_AUTH="admin:${SPLUNK_PASSWORD}"
    else
        echo "extract-spl-groupby.sh: SPLUNK_AUTH not set (e.g. admin:<password>) and SPLUNK_PASSWORD also unset" >&2
        exit 1
    fi
fi

curl_tls_flags=()
if [[ "${SPLUNK_INSECURE:-0}" == "1" ]]; then
    curl_tls_flags+=(-k)
fi

# macOS/BSD mktemp requires an explicit -t template; the bare form fails there.
RESP_FILE=$(mktemp -t extract-spl-groupby.XXXXXX)
trap 'rm -f "$RESP_FILE"' EXIT

curl_exit=0
HTTP_CODE=$(curl -sS "${curl_tls_flags[@]}" \
    -u "$SPLUNK_AUTH" \
    --get \
    --data-urlencode "q=${SPL}" \
    --data-urlencode "parse_only=1" \
    --data-urlencode "output_mode=json" \
    --output "$RESP_FILE" \
    --write-out '%{http_code}' \
    "${SPLUNK_URL}/services/search/parser") || curl_exit=$?  # || prevents set -e from firing before we can emit the diagnostic

if [[ "$curl_exit" -ne 0 ]]; then
    echo "extract-spl-groupby.sh: parser REST call failed (curl exit $curl_exit, no HTTP response from ${SPLUNK_URL}/services/search/parser)" >&2
    exit 1
fi

if [[ ! "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
    echo "extract-spl-groupby.sh: parser REST call returned HTTP ${HTTP_CODE}" >&2
    if [[ -s "$RESP_FILE" ]]; then
        cat "$RESP_FILE" >&2
    fi
    exit 1
fi

RESP=$(cat "$RESP_FILE")

# Each stats-like or transaction command overwrites the running fields tuple;
# the last such command's by-clause wins. A rename after aggregation rewrites
# field names through explicit "A AS B" pairs. Results are emitted as a single
# compact JSON object so bash can extract each piece by key.
STATE=$(echo "$RESP" | jq -c '
    .commands as $cmds
    | reduce ($cmds // [])[] as $cmd (
        {tier: "per_event", fields: [], post_lookup: false, dropped_fields: []};
        ($cmd.command // "") as $name
        | if ($name == "stats" or $name == "chart" or $name == "timechart" or $name == "tstats") then
            ($cmd.args["groupby-fields"] // []) as $f
            | .tier           = (if ($f | length) > 0 then "per_group" else "count_only" end)
            | .fields         = $f
            | .post_lookup    = false
            | .dropped_fields = []
          elif $name == "transaction" then
            (($cmd.rawargs // "") | split(" ")
              | map(select(. != "" and (test("=") | not)
                           and . != "keepevicted"
                           and . != "mvlist"
                           and . != "unifyends"))) as $f
            | .tier           = "per_group"
            | .fields         = $f
            | .post_lookup    = false
            | .dropped_fields = []
          elif $name == "rename" then
            (($cmd.rawargs // "")
              | [scan("([A-Za-z_][A-Za-z0-9_.*]*)\\s+[Aa][Ss]\\s+([A-Za-z_][A-Za-z0-9_.*]*)")]
              | map({from: .[0], to: .[1]})) as $clauses
            | .fields = (.fields | map(. as $f
                | reduce $clauses[] as $c ($f;
                    if . == $c.from then $c.to else . end)))
          elif $name == "lookup" and .tier == "per_group" then
            .post_lookup = true
          elif $name == "fields" and .tier == "per_group" then
            (($cmd.rawargs // "") | sub("^\\s+"; "")) as $args
            | if ($args | startswith("-")) then
                # Splunk accepts both comma-separated (`fields - a, b`)
                # and space-separated (`fields - a b`) forms (and a
                # mix). Normalise any run of commas/whitespace into a
                # single comma before splitting so all three shapes
                # produce the same field list.
                ($args
                  | ltrimstr("-")
                  | gsub("^\\s+|\\s+$"; "")
                  | gsub("[,\\s]+"; ",")
                  | split(",")
                  | map(select(. != ""))) as $removed
                | . as $st
                | .dropped_fields = (.dropped_fields + ($removed | map(select(. as $r | any($st.fields[]; . == $r)))))
              else . end
          else . end)
')

TIER=$(echo "$STATE" | jq -r '.tier')
GROUP_BY=$(echo "$STATE" | jq -r 'if .tier == "per_group" then .fields[] else empty end')
POST_LOOKUP=$(echo "$STATE" | jq -r '.post_lookup')
DROPPED=$(echo "$STATE" | jq -r '.dropped_fields | join(",")')

if [[ "$TIER" != "per_group" || -z "$GROUP_BY" ]]; then
    echo "extract-spl-groupby.sh: no group-by tuple found (count-only or no aggregation)" >&2
    exit 1
fi

if [[ "$POST_LOOKUP" == "true" ]]; then
    echo "extract-spl-groupby.sh: warning: post-aggregation 'lookup' detected — group-by tuple usually still appears in result rows, but verify before committing the correlation map" >&2
fi

if [[ -n "$DROPPED" ]]; then
    echo "extract-spl-groupby.sh: warning: post-aggregation 'fields -' drops group-by field(s): ${DROPPED} — these will NOT appear in result rows" >&2
fi

echo "$GROUP_BY"
