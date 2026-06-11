#!/usr/bin/env bash
# extract-spl-groupby.sh
#
# Internal: implementation detail of the scenario-authoring skill
# (.claude/skills/scenario-authoring/SKILL.md). Not a stable CLI; flag names,
# output, and exit codes may change without notice.
#
# Extract the final group-by tuple from a detection SPL. Parses the SPL
# text statically; when SPLUNK_URL and SPLUNK_AUTH are set, cross-checks
# via Splunk's /services/search/parser REST endpoint and walks the
# parsed command tree. Mirrors the TA's _classify_commands /
# _classify_rewritten_commands semantics.
#
# Usage: extract-spl-groupby.sh "<spl>"
# Output: one field name per line on stdout, exit 0 on success.
# Exit 1 on no aggregation / count-only / parser refusal / no fields,
#        or when SPLUNK_URL is unset (Splunk cross-check falls back to
#        static-only behavior — the caller is informed via stderr).
# Exit 2 on usage error.
#
# Env vars (all optional for static-only analysis):
#   SPLUNK_URL       — Splunk management endpoint
#                      (e.g. https://splunk.example.com:8089).
#                      If unset, REST cross-check is skipped; the script
#                      emits a notice and exits 1 with no output.
#   SPLUNK_AUTH      — Splunk credentials as user:password.
#                      If unset and SPLUNK_PASSWORD is set, defaults to
#                      admin:${SPLUNK_PASSWORD}; otherwise required when
#                      SPLUNK_URL is set.
#   SPLUNK_INSECURE  — unset/0: verify the TLS chain (default).
#                      1: pass curl -k (opt in for self-signed certs).
#
# Rename projection covers the floor of what the TA's _parse_rename
# handles: explicit "A AS B" pairs (case-insensitive on AS), single or
# comma-separated. Wildcard prefix-strip / prefix-add / prefix-replace
# forms (e.g. `rename Authentication.* AS *`) are not handled here —
# add them when a real detection demands them.
#
# Post-aggregation `lookup` and `fields - <group_by>` projections are
# also out of scope: lookup adds enrichment fields (the group-by tuple
# usually still appears in result rows, so output is correct) and
# `fields -` may strip them. Both emit a stderr warning so the author
# verifies the result-row shape before committing the correlation map.

set -euo pipefail

# Preflight: curl and jq are hard-required. Mirrors the preflight
# pattern in fetch-dataset.sh so a missing dep fails with an actionable
# message instead of the generic `command not found` from `set -e`.
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

# curl_tls_flags: empty by default (verify the cert chain). SPLUNK_INSECURE=1
# opts in to -k for stock local Splunk's self-signed mgmt cert.
curl_tls_flags=()
if [[ "${SPLUNK_INSECURE:-0}" == "1" ]]; then
    curl_tls_flags+=(-k)
fi

# GET /services/search/parser?q=<spl>&parse_only=1&output_mode=json —
# matches the TA's parse_spl_group_by_fields invocation.
#
# Capture body to a tmpfile and the HTTP code via -w so we can
# distinguish transport-level failure (curl exit non-zero, no HTTP
# response) from application-level failure (4xx/5xx with an error
# body). The `|| curl_exit=$?` form is load-bearing: without it,
# `set -e` aborts the script the moment curl fails, before we can
# emit the diagnostic.
# Bare `mktemp` works on modern macOS but older BSD mktemp requires a
# template; the explicit -t form covers both.
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
    "${SPLUNK_URL}/services/search/parser") || curl_exit=$?

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

# Walk the command list, mirroring the TA's _classify_commands. Each
# stats-like / transaction command overwrites the running fields tuple
# so the final aggregating command wins. A `rename` after that command
# projects each field through any explicit AS pairs we can parse.
#
# `post_lookup` flips to true when a `lookup` appears after the final
# aggregation; `dropped_fields` collects names removed by `fields - X`
# after the final aggregation. Both are surfaced as warnings (not
# failures) so the author verifies the result-row shape before
# committing the correlation map. The script's job is the GROUP-BY
# tuple — those are the canonical correlation keys when lookup merely
# enriches; `fields -` is the case where the assumption breaks.
#
# jq emits a single compact JSON object so the bash side can pull each
# piece by key without conflating metadata with the field list.
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
