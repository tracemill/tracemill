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

@test "auto-detect: sectioned ActiveDirectory records classify as admon" {
  { printf '%*s\n' 240 ''; printf 'dcName=dc1\nNames:\n\tname=Alice\n'; } > "$BATS_TEST_TMPDIR/admon.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/admon.log" \
    --key name --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "admon" ]
}

@test "auto-detect: all-CRLF ActiveDirectory records classify as admon" {
  printf 'dcName=dc1\r\nNames:\r\n\tname=Alice\r\n' > "$BATS_TEST_TMPDIR/admon.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/admon.log" \
    --key name --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "admon" ]
}

@test "auto-detect: one-line kv beginning with dcName stays kv" {
  printf 'dcName=dc1 user=alice\n' > "$BATS_TEST_TMPDIR/dc-kv.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/dc-kv.log" \
    --key dcName --mode summary
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

@test "auto-detect: later standalone dcName does not hijack plain text" {
  printf 'This file contains prose.\ndcName=dc1\n' > "$BATS_TEST_TMPDIR/prose.txt"
  run extract_events --dataset "$BATS_TEST_TMPDIR/prose.txt" \
    --key ignored --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "text" ]
}

@test "auto-detect: later standalone dcName does not hijack generic kv" {
  printf 'EventCode=4624 user=alice\ndcName=dc1\n' > "$BATS_TEST_TMPDIR/kv.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv.log" \
    --key EventCode --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "kv" ]
}
