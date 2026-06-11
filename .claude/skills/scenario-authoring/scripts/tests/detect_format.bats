#!/usr/bin/env bats

# detect_format is exercised through the extract-events.sh dispatcher (no
# separate binary). Tests here drive --format auto and inspect the
# reported .format in the summary output.

load helpers

setup() { scenario_authoring_setup; }

@test "auto-detect: pretty-printed JSON is json (not ndjson)" {
  run extract_events --dataset "$FIXTURES/dataset-cloudtrail.json" \
    --key eventName --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "json" ]
}

@test "auto-detect: true NDJSON (two values) is ndjson" {
  printf '{"a":1}\n{"a":2}\n' > "$BATS_TEST_TMPDIR/x.ndjson"
  run extract_events --dataset "$BATS_TEST_TMPDIR/x.ndjson" --key a --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "ndjson" ]
}

@test "auto-detect: UTF-8 BOM + JSON classifies as json" {
  printf '\xef\xbb\xbf{"a":1}\n' > "$BATS_TEST_TMPDIR/bom.json"
  run extract_events --dataset "$BATS_TEST_TMPDIR/bom.json" --key a --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "json" ]
}

@test "auto-detect: leading whitespace + JSON classifies as json" {
  printf '   \n  {"a":1}\n' > "$BATS_TEST_TMPDIR/ws.json"
  run extract_events --dataset "$BATS_TEST_TMPDIR/ws.json" --key a --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "json" ]
}

@test "auto-detect: XML is xml" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --key "System/EventID" --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "xml" ]
}

@test "auto-detect: key=value lines classify as kv" {
  cat > "$BATS_TEST_TMPDIR/data.log" <<'EOF'
EventCode=4624 user=alice
EventCode=4625 user=bob
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/data.log" \
    --key EventCode --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "kv" ]
}

@test "auto-detect: plain prose classifies as text" {
  cat > "$BATS_TEST_TMPDIR/prose.txt" <<'EOF'
This file contains nothing structured.
Second line of prose.
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/prose.txt" \
    --key ignored --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "text" ]
}
