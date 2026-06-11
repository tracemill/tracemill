#!/usr/bin/env bats
# Tests for extract-spl-groupby.sh — the script that classifies a Splunk
# detection's SPL via the parser REST endpoint and surfaces the final
# group-by tuple, applying explicit-AS rename projection on the way.
#
# Each test starts a fresh mock_splunk.py with a parser-shaped body that
# matches what Splunk's /services/search/parser endpoint would return for
# the test's SPL. The script reads SPLUNK_URL + SPLUNK_AUTH from env; the
# tests point both at the local mock.

load helpers

setup() {
    scenario_authoring_setup
    export SPLUNK_AUTH="test:test"
}

teardown() {
    stop_mock_splunk
}

# write_parser_config <config-path> <body-json>
# Writes a mock_splunk.py config that returns 200 with <body-json> for
# /services/search/parser.
write_parser_config() {
    local cfg="$1" body="$2"
    cat > "$cfg" <<JSON
{
  "responses": {"/services/search/parser": [200]},
  "bodies":    {"/services/search/parser": ${body}}
}
JSON
}

@test "extracts by-clause from final stats" {
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "stats",  "rawargs": "count by user src_ip",
         "args": {"groupby-fields": ["user", "src_ip"]}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | stats count by user src_ip'
    [ "$status" -eq 0 ]
    [[ "$output" == *"user"* ]]
    [[ "$output" == *"src_ip"* ]]
}

@test "projects through rename chain (explicit AS pairs)" {
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "stats",  "rawargs": "count by Authentication.user",
         "args": {"groupby-fields": ["Authentication.user"]}},
        {"command": "rename", "rawargs": "Authentication.user AS user",
         "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | stats count by Authentication.user | rename Authentication.user AS user'
    [ "$status" -eq 0 ]
    [[ "$output" == *"user"* ]]
    [[ "$output" != *"Authentication.user"* ]]
}

@test "exits non-zero on no aggregation" {
    body='{
      "commands": [
        {"command": "search",
         "rawargs": "index=main eventCode=4625",
         "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main eventCode=4625'
    [ "$status" -ne 0 ]
}

@test "exits non-zero on count_only (no by-clause)" {
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "stats",  "rawargs": "count", "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | stats count'
    [ "$status" -ne 0 ]
}

@test "ESCU drop_dm_object_name pattern returns post-rename names" {
    # Common ESCU pattern: tstats by Authentication.user, then drop the
    # "Authentication." prefix via explicit AS pairs.
    body='{
      "commands": [
        {"command": "tstats",
         "rawargs": "count from datamodel=Authentication.Authentication by Authentication.user Authentication.src",
         "args": {"groupby-fields": ["Authentication.user", "Authentication.src"]}},
        {"command": "rename",
         "rawargs": "Authentication.user AS user, Authentication.src AS src",
         "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            '| tstats count from datamodel=Authentication.Authentication by Authentication.user Authentication.src | rename Authentication.user AS user, Authentication.src AS src'
    [ "$status" -eq 0 ]
    [[ "$output" == *"user"* ]]
    [[ "$output" == *"src"* ]]
    [[ "$output" != *"Authentication.user"* ]]
}

@test "non-tstats with rename after stats also extracts post-rename names" {
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "stats",  "rawargs": "count by user_dn",
         "args": {"groupby-fields": ["user_dn"]}},
        {"command": "rename", "rawargs": "user_dn AS user", "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | stats count by user_dn | rename user_dn AS user'
    [ "$status" -eq 0 ]
    [[ "$output" == *"user"* ]]
    [[ "$output" != *"user_dn"* ]]
}

@test "transaction with by-tokens" {
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "transaction",
         "rawargs": "src_ip user maxspan=5m",
         "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | transaction src_ip user maxspan=5m'
    [ "$status" -eq 0 ]
    [[ "$output" == *"src_ip"* ]]
    [[ "$output" == *"user"* ]]
    [[ "$output" != *"maxspan"* ]]
}

@test "missing argument exits 2" {
    run "$SCRIPTS_DIR/extract-spl-groupby.sh"
    [ "$status" -eq 2 ]
}

@test "missing SPLUNK_URL exits non-zero with actionable message" {
    run env -u SPLUNK_URL "$SCRIPTS_DIR/extract-spl-groupby.sh" 'search index=main'
    [ "$status" -ne 0 ]
    [[ "$output" == *"SPLUNK_URL"* ]]
}

# write_parser_config_status <config-path> <body-json> <status-code>
# Variant of write_parser_config that lets a test pin the HTTP status
# returned by the mock for /services/search/parser. Used for the
# 4xx/5xx debuggability tests.
write_parser_config_status() {
    local cfg="$1" body="$2" code="$3"
    cat > "$cfg" <<JSON
{
  "responses": {"/services/search/parser": [${code}]},
  "bodies":    {"/services/search/parser": ${body}}
}
JSON
}

@test "non-2xx HTTP from parser includes status and response body" {
    body='{"messages":[{"type":"FATAL","text":"unauthorized: missing or invalid token"}]}'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config_status "$cfg" "$body" 401
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" 'search index=main | stats count by user'
    [ "$status" -ne 0 ]
    [[ "$output" == *"HTTP 401"* ]]
    [[ "$output" == *"unauthorized"* ]]
}

@test "5xx HTTP from parser also reported with status" {
    body='{"messages":[{"type":"ERROR","text":"backend down"}]}'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config_status "$cfg" "$body" 503
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" 'search index=main | stats count by user'
    [ "$status" -ne 0 ]
    [[ "$output" == *"HTTP 503"* ]]
}

@test "post-aggregation lookup warns but still returns group-by tuple" {
    # Common ESCU shape: stats by foo | lookup t foo OUTPUT bar.
    # The script's job is the group-by tuple; lookup typically
    # enriches the row without dropping the group-by, so the output
    # is still usable. Surface a warning so the author verifies.
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "stats",  "rawargs": "count by user",
         "args": {"groupby-fields": ["user"]}},
        {"command": "lookup", "rawargs": "user_meta user OUTPUT department",
         "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | stats count by user | lookup user_meta user OUTPUT department'
    [ "$status" -eq 0 ]
    [[ "$output" == *"user"* ]]
    # The warning goes to stderr, which `run` merges into $output.
    [[ "$output" == *"warning"* ]]
    [[ "$output" == *"lookup"* ]]
}

@test "post-aggregation 'fields - X' on a group-by field warns by name" {
    # The dangerous case: an explicit fields - drops a group-by from
    # the result row. Surface the dropped field name so the author
    # sees the mismatch immediately.
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "stats",  "rawargs": "count by user src",
         "args": {"groupby-fields": ["user", "src"]}},
        {"command": "fields", "rawargs": " - user", "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | stats count by user src | fields - user'
    [ "$status" -eq 0 ]
    [[ "$output" == *"warning"* ]]
    [[ "$output" == *"user"* ]]
}

@test "post-aggregation 'fields - a b' (space-separated) names each dropped group-by field" {
    # Splunk accepts space-separated field lists in `fields -`; the
    # warning must fire on each group-by field, not silently miss them
    # because the regex only knew about commas.
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "stats",  "rawargs": "count by user src",
         "args": {"groupby-fields": ["user", "src"]}},
        {"command": "fields", "rawargs": " - user src", "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | stats count by user src | fields - user src'
    [ "$status" -eq 0 ]
    [[ "$output" == *"warning"* ]]
    [[ "$output" == *"user"* ]]
    [[ "$output" == *"src"* ]]
}

@test "post-aggregation 'fields - X' that doesn't drop a group-by field stays silent" {
    # Sanity check: `fields -` on a non-group-by field must not warn.
    body='{
      "commands": [
        {"command": "search", "rawargs": "index=main", "args": {}},
        {"command": "stats",  "rawargs": "count by user",
         "args": {"groupby-fields": ["user"]}},
        {"command": "fields", "rawargs": " - count", "args": {}}
      ]
    }'
    cfg="$BATS_TEST_TMPDIR/cfg.json"
    log="$BATS_TEST_TMPDIR/log.jsonl"
    write_parser_config "$cfg" "$body"
    start_mock_splunk "$cfg" "$log"
    SPLUNK_URL="$MOCK_SPLUNK_URL" \
        run "$SCRIPTS_DIR/extract-spl-groupby.sh" \
            'search index=main | stats count by user | fields - count'
    [ "$status" -eq 0 ]
    [[ "$output" == *"user"* ]]
    [[ "$output" != *"fields -"* ]]
}
