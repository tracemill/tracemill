#!/usr/bin/env bats

load helpers

setup() {
  scenario_authoring_setup
  export OUT_FILE="$BATS_TEST_TMPDIR/sample"
}

@test "extract XML: matching event written, sample_path emitted" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --format xml --key "System/EventID" --mode extract \
    --value "10" --out "$OUT_FILE.xml"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.sample_path')" = "$OUT_FILE.xml" ]
  grep -q '<EventID>10</EventID>' "$OUT_FILE.xml"
}

@test "extract XML: no match → exit 1, no partial output" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --format xml --key "System/EventID" --mode extract \
    --value "9999" --out "$OUT_FILE.xml"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no event matched"* ]]
  # The previous round's bug: `null` sneaking past the empty-file guard.
  # The file should be empty (or not contain "null").
  ! grep -q '<Event>null</Event>' "$OUT_FILE.xml" 2>/dev/null || false
}

@test "extract JSON: dotted-path key resolves nested field" {
  cat > "$BATS_TEST_TMPDIR/nested.json" <<'EOF'
[
  {"userIdentity":{"userName":"alice","type":"IAMUser"}},
  {"userIdentity":{"userName":"bob","type":"AssumedRole"}}
]
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/nested.json" \
    --format json --key "userIdentity.userName" --mode extract \
    --value "bob" --out "$OUT_FILE.json"
  [ "$status" -eq 0 ]
  [ "$(jq -r '.userIdentity.userName' "$OUT_FILE.json")" = "bob" ]
}

@test "extract JSON: no match → exit 1, not 'null'" {
  run extract_events --dataset "$FIXTURES/dataset-cloudtrail.json" \
    --format json --key eventName --mode extract \
    --value "Nonexistent" --out "$OUT_FILE.json"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no event matched"* ]]
}

@test "extract NDJSON: dotted-path key" {
  cat > "$BATS_TEST_TMPDIR/nested.ndjson" <<'EOF'
{"userIdentity":{"userName":"alice"}}
{"userIdentity":{"userName":"bob"}}
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/nested.ndjson" \
    --format ndjson --key "userIdentity.userName" --mode extract \
    --value "bob" --out "$OUT_FILE.ndjson"
  [ "$status" -eq 0 ]
  [ "$(jq -r '.userIdentity.userName' "$OUT_FILE.ndjson")" = "bob" ]
}

@test "extract kv: first line matching KEY=VALUE" {
  cat > "$BATS_TEST_TMPDIR/kv.log" <<'EOF'
EventCode=4624 user=alice
EventCode=4625 user=bob
EventCode=4624 user=carol
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv.log" \
    --format kv --key EventCode --mode extract \
    --value "4625" --out "$OUT_FILE.log"
  [ "$status" -eq 0 ]
  grep -q "user=bob" "$OUT_FILE.log"
}

@test "extract admon: matching complete record is written" {
  printf 'dcName=dc1\nNames:\n\tname=Alice\ndcName=dc2\nNames:\n\tname=Bob\n' > "$BATS_TEST_TMPDIR/admon.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/admon.log" \
    --format admon --key name --mode extract \
    --value "Bob" --out "$OUT_FILE.log"
  [ "$status" -eq 0 ]
  grep -q '^dcName=dc2$' "$OUT_FILE.log"
  grep -q $'^\tname=Bob$' "$OUT_FILE.log"
  ! grep -q '^dcName=dc1$' "$OUT_FILE.log"
}

@test "extract admon: parse failures are attributed to the helper" {
  printf 'Names:\n' > "$BATS_TEST_TMPDIR/bad.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/bad.log" \
    --format admon --key name --mode extract \
    --value Alice --out "$OUT_FILE.log"
  [ "$status" -eq 1 ]
  [[ "$output" == "_extract-events-extract.sh: cannot parse ActiveDirectory admon KV"* ]]
  [[ "$output" == *"section header before record-start dcName"* ]]
}

@test "extract text: VALUE=all returns first non-empty line" {
  printf '\nfirst line\nsecond line\n' > "$BATS_TEST_TMPDIR/plain.txt"
  run extract_events --dataset "$BATS_TEST_TMPDIR/plain.txt" \
    --format text --key anything --mode extract \
    --value "all" --out "$OUT_FILE.log"
  [ "$status" -eq 0 ]
  [ "$(cat "$OUT_FILE.log")" = "first line" ]
}

@test "--key required for extract mode" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --mode extract --value "10" --out "$OUT_FILE.xml"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--key required"* ]]
}

@test "--value required for extract mode" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --format xml --key "System/EventID" --mode extract --out "$OUT_FILE.xml"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--value required"* ]]
}

# ── Stale-$OUT truncation on no-match (regression: NDJSON branch) ─────────────

@test "extract NDJSON: no-match clears a pre-existing \$OUT (stale content never lingers)" {
  cat > "$BATS_TEST_TMPDIR/events.ndjson" <<'EOF'
{"userName":"alice"}
{"userName":"bob"}
EOF
  # Seed $OUT with stale content from a prior run. The no-match branch
  # must truncate it BEFORE checking [[ ! -s "$OUT" ]]; otherwise the
  # guard would treat stale bytes as a successful match.
  printf 'STALE CONTENT FROM A PRIOR RUN\n' > "$OUT_FILE.ndjson"
  [ -s "$OUT_FILE.ndjson" ]

  run extract_events --dataset "$BATS_TEST_TMPDIR/events.ndjson" \
    --format ndjson --key userName --mode extract \
    --value "nobody" --out "$OUT_FILE.ndjson"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no event matched"* ]]
  # File must be empty (or at minimum not contain the stale sentinel).
  ! grep -q 'STALE CONTENT' "$OUT_FILE.ndjson"
}

@test "extract NDJSON: match overwrites pre-existing \$OUT cleanly" {
  cat > "$BATS_TEST_TMPDIR/events.ndjson" <<'EOF'
{"userName":"alice"}
{"userName":"bob"}
EOF
  printf 'STALE CONTENT\n' > "$OUT_FILE.ndjson"

  run extract_events --dataset "$BATS_TEST_TMPDIR/events.ndjson" \
    --format ndjson --key userName --mode extract \
    --value "bob" --out "$OUT_FILE.ndjson"
  [ "$status" -eq 0 ]
  # File now contains only the matched event — no stale prefix/suffix.
  ! grep -q 'STALE CONTENT' "$OUT_FILE.ndjson"
  [ "$(jq -r .userName "$OUT_FILE.ndjson")" = "bob" ]
}

# ── kv extract: tolerant whitespace splitting ────────────────────────────────
# Same root cause as the summary/samples kv tests: pre-fix `awk -F'[= ]'`
# mis-paired fields when delimiters repeated.

@test "extract kv: multiple spaces between tokens still match KEY=VALUE" {
  printf 'EventCode=4624  user=alice\nEventCode=4625  user=bob\nEventCode=4624  user=carol\n' \
    > "$BATS_TEST_TMPDIR/kv-spaces.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-spaces.log" \
    --format kv --key EventCode --mode extract \
    --value "4625" --out "$OUT_FILE.log"
  [ "$status" -eq 0 ]
  grep -q 'user=bob' "$OUT_FILE.log"
}

@test "extract kv: tab-separated tokens still match KEY=VALUE" {
  printf 'EventCode=4624\tuser=alice\nEventCode=4625\tuser=bob\n' \
    > "$BATS_TEST_TMPDIR/kv-tabs.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-tabs.log" \
    --format kv --key EventCode --mode extract \
    --value "4625" --out "$OUT_FILE.log"
  [ "$status" -eq 0 ]
  grep -q 'user=bob' "$OUT_FILE.log"
}

@test "extract kv: leading whitespace on lines does not block the match" {
  printf '  EventCode=4624 user=alice\n  EventCode=4625 user=bob\n' \
    > "$BATS_TEST_TMPDIR/kv-indent.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-indent.log" \
    --format kv --key EventCode --mode extract \
    --value "4625" --out "$OUT_FILE.log"
  [ "$status" -eq 0 ]
  grep -q 'user=bob' "$OUT_FILE.log"
}
