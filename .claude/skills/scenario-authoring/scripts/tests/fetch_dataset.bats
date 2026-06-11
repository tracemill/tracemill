#!/usr/bin/env bats

load helpers

setup() {
  scenario_authoring_setup
  export FETCH="$SCRIPTS_DIR/fetch-dataset.sh"
}

# Wrapper around the shared helper that asserts success at the call site
# so a port-detection failure surfaces as a meaningful test failure rather
# than letting the test proceed with an unset $SERVER_PORT.
start_server() {
  start_local_server "$1" || {
    echo "start_server: failed to launch http.server in $1" >&2
    return 1
  }
}

teardown() {
  stop_local_server
}

@test "fetch-dataset: caches .json extension from a simple URL" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf '{"k":1}\n' > "$doc/sample.json"
  start_server "$doc"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/sample.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"/attack_data/"*".json" ]]
  [ -f "$output" ]
}

@test "fetch-dataset: URL with ?query preserves extension (PR 242 review #5)" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf '{"k":1}\n' > "$doc/sample.json"
  start_server "$doc"

  # Python's http.server ignores query strings; the response bytes are the
  # same. The test verifies that the CACHE FILENAME still ends in .json
  # despite the ?token=abc suffix.
  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/sample.json?token=abc&plain=1"
  [ "$status" -eq 0 ]
  [[ "$output" == *.json ]]
}

@test "fetch-dataset: URL with #fragment preserves extension" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf '<Events/>\n' > "$doc/sample.xml"
  start_server "$doc"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/sample.xml#section"
  [ "$status" -eq 0 ]
  [[ "$output" == *.xml ]]
}

@test "fetch-dataset: idempotent — same URL twice writes one cache entry" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf '{"k":1}\n' > "$doc/sample.json"
  start_server "$doc"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/sample.json"
  [ "$status" -eq 0 ]
  first="$output"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/sample.json"
  [ "$status" -eq 0 ]
  [ "$output" = "$first" ]

  count="$(ls "$SCENARIO_AUTHORING_CACHE/attack_data" | wc -l | tr -d ' ')"
  [ "$count" -eq 1 ]
}

@test "fetch-dataset: no args → usage, exit 2" {
  run "$FETCH"
  [ "$status" -eq 2 ]
  [[ "$output" == *"usage:"* ]]
}

@test "fetch-dataset: bad URL → exit 1" {
  run "$FETCH" "http://127.0.0.1:1/nope.json"
  [ "$status" -eq 1 ]
  [[ "$output" == *"failed to fetch"* ]]
}

# ── Extension-whitelist corner cases ──────────────────────────────────────────

@test "fetch-dataset: URL with no recognised extension → bare sha cache path" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf 'some bytes\n' > "$doc/README.md"
  start_server "$doc"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/README.md"
  [ "$status" -eq 0 ]
  # .md is NOT in the whitelist (.log|.xml|.json|.ndjson|.jsonl|.csv|.txt).
  # The cache filename must be a bare sha with no extension.
  [[ "$output" == */attack_data/* ]]
  basename="${output##*/}"
  # 64-char hex sha, no trailing '.'
  [[ "$basename" =~ ^[a-f0-9]{64}$ ]]
}

@test "fetch-dataset: URL ending in .log preserves .log extension" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf 'logline\n' > "$doc/attack.log"
  start_server "$doc"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/attack.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *.log ]]
}

@test "fetch-dataset: URL ending in .ndjson preserves .ndjson extension" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf '{"a":1}\n{"a":2}\n' > "$doc/events.ndjson"
  start_server "$doc"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/events.ndjson"
  [ "$status" -eq 0 ]
  [[ "$output" == *.ndjson ]]
}

@test "fetch-dataset: URL with both ? and # chops both before extension match" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf '{}\n' > "$doc/f.json"
  start_server "$doc"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/f.json?k=v#frag"
  [ "$status" -eq 0 ]
  [[ "$output" == *.json ]]
}

@test "fetch-dataset: same content via different query strings → single cache entry" {
  # Extension is preserved from the stripped URL_PATH; sha is computed
  # over the fetched bytes. Two URLs with different query strings but
  # identical payloads must collide on the same cache entry.
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf '{"x":1}\n' > "$doc/shared.json"
  start_server "$doc"

  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/shared.json?v=1"
  [ "$status" -eq 0 ]
  a="$output"
  run "$FETCH" "http://127.0.0.1:$SERVER_PORT/shared.json?v=2"
  [ "$status" -eq 0 ]
  b="$output"
  [ "$a" = "$b" ]
  [ "$(ls "$SCENARIO_AUTHORING_CACHE/attack_data" | wc -l | tr -d ' ')" -eq 1 ]
}
