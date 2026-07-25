#!/usr/bin/env bats

load helpers

setup() { scenario_authoring_setup; }

@test "summary XML: three events, EID=10 count 2, EID=1 count 1" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --format xml --key "System/EventID" --mode summary
  [ "$status" -eq 0 ]
  total="$(echo "$output" | jq '.total')"
  fmt="$(echo "$output" | jq -r '.format')"
  eid10="$(echo "$output" | jq '.groups[] | select(.key=="10") | .count')"
  eid1="$(echo "$output" | jq '.groups[] | select(.key=="1") | .count')"
  [ "$fmt" = "xml" ]
  [ "$total" -eq 3 ]
  [ "$eid10" -eq 2 ]
  [ "$eid1" -eq 1 ]
}

@test "summary JSON: three records, DeleteTrail 2, CreateAccessKey 1" {
  run extract_events --dataset "$FIXTURES/dataset-cloudtrail.json" \
    --format json --key eventName --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "json" ]
  [ "$(echo "$output" | jq '.total')" -eq 3 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="DeleteTrail") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="CreateAccessKey") | .count')" -eq 1 ]
}

@test "summary NDJSON: nested dotted-path key resolves groups" {
  cat > "$BATS_TEST_TMPDIR/nested.ndjson" <<'EOF'
{"userIdentity":{"userName":"alice"},"region":"us-east-1"}
{"userIdentity":{"userName":"bob"},"region":"us-west-2"}
{"userIdentity":{"userName":"alice"},"region":"eu-west-1"}
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/nested.ndjson" \
    --format ndjson --key "userIdentity.userName" --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 3 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="alice") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="bob") | .count')" -eq 1 ]
}

@test "summary NDJSON: blank lines are filtered from total" {
  # Three valid events with one blank line between them — total must be 3,
  # not 4.
  cat > "$BATS_TEST_TMPDIR/blanks.ndjson" <<'EOF'
{"a":1}

{"a":2}
{"a":3}
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/blanks.ndjson" \
    --format ndjson --key a --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 3 ]
}

@test "summary kv: group by EventCode" {
  cat > "$BATS_TEST_TMPDIR/kv.log" <<'EOF'
EventCode=4624 user=alice
EventCode=4625 user=bob
EventCode=4624 user=carol
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv.log" \
    --format kv --key EventCode --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="4624") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="4625") | .count')" -eq 1 ]
}

@test "summary admon: groups complete records by a bare field" {
  printf 'dcName=dc1\nNames:\n\tname=Alice\ndcName=dc2\nNames:\n\tname=Bob\ndcName=dc3\nNames:\n\tname=Alice\n' \
    > "$BATS_TEST_TMPDIR/admon.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/admon.log" \
    --format admon --key name --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.format')" = "admon" ]
  [ "$(echo "$output" | jq '.total')" -eq 3 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="Alice") | .count')" -eq 2 ]
}

@test "summary admon: parse failures are attributed to the helper" {
  printf 'Names:\n' > "$BATS_TEST_TMPDIR/bad.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/bad.log" \
    --format admon --key name --mode summary
  [ "$status" -eq 1 ]
  [[ "$output" == "_extract-events-summary.sh: cannot parse ActiveDirectory admon KV"* ]]
  [[ "$output" == *"section header before record-start dcName"* ]]
}

@test "summary text: reports single 'all' group" {
  printf 'line one\nline two\nline three\n' > "$BATS_TEST_TMPDIR/plain.txt"
  run extract_events --dataset "$BATS_TEST_TMPDIR/plain.txt" \
    --format text --key anything --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.groups[0].key')" = "all" ]
  [ "$(echo "$output" | jq '.groups[0].count')" -eq 3 ]
}

@test "--key required for summary mode" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" --mode summary
  [ "$status" -eq 2 ]
  [[ "$output" == *"--key required"* ]]
}

# ── Non-adjacent duplicate keys (group_by correctness) ─────────────────────────
# jq's group_by(.) sorts its input internally, so non-contiguous repeats of
# the same key must still land in a single group. These tests prove the
# behavior across all formats (the previous tests happened to use only
# adjacent duplicates, which wouldn't have caught a regression).

@test "summary JSON: non-adjacent duplicate keys (A,B,A) → one group with count 2" {
  cat > "$BATS_TEST_TMPDIR/abaa.json" <<'EOF'
{"Records":[
  {"eventName":"A","region":"us-east-1"},
  {"eventName":"B","region":"us-west-2"},
  {"eventName":"A","region":"eu-west-1"}
]}
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/abaa.json" \
    --format json --key eventName --mode summary
  [ "$status" -eq 0 ]
  # Exactly two groups (A, B), not three. Count for A must be 2.
  [ "$(echo "$output" | jq '.groups | length')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="A") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="B") | .count')" -eq 1 ]
}

@test "summary NDJSON: non-adjacent duplicate keys (A,B,A) → one group with count 2" {
  cat > "$BATS_TEST_TMPDIR/aba.ndjson" <<'EOF'
{"k":"A"}
{"k":"B"}
{"k":"A"}
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/aba.ndjson" \
    --format ndjson --key k --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.groups | length')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="A") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="B") | .count')" -eq 1 ]
}

@test "summary XML: non-adjacent duplicate EIDs (10,1,10) → one group with count 2" {
  cat > "$BATS_TEST_TMPDIR/aba.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>10</EventID></System></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID></System></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>10</EventID></System></Event>
</Events>
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/aba.xml" \
    --format xml --key "System/EventID" --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.groups | length')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="10") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="1") | .count')" -eq 1 ]
}

@test "summary kv: non-adjacent duplicate values (A,B,A) → one group with count 2" {
  cat > "$BATS_TEST_TMPDIR/aba.log" <<'EOF'
EventCode=A user=alice
EventCode=B user=bob
EventCode=A user=carol
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/aba.log" \
    --format kv --key EventCode --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.groups | length')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="A") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="B") | .count')" -eq 1 ]
}

# ── Small-dataset edge cases ──────────────────────────────────────────────────

@test "summary JSON: single-event dataset → total=1, one group count=1" {
  printf '[{"k":"solo"}]\n' > "$BATS_TEST_TMPDIR/one.json"
  run extract_events --dataset "$BATS_TEST_TMPDIR/one.json" \
    --format json --key k --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 1 ]
  [ "$(echo "$output" | jq '.groups | length')" -eq 1 ]
  [ "$(echo "$output" | jq -r '.groups[0].key')" = "solo" ]
  [ "$(echo "$output" | jq '.groups[0].count')" -eq 1 ]
}

@test "summary NDJSON: empty dataset → total=0, empty groups" {
  : > "$BATS_TEST_TMPDIR/empty.ndjson"
  run extract_events --dataset "$BATS_TEST_TMPDIR/empty.ndjson" \
    --format ndjson --key k --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 0 ]
  [ "$(echo "$output" | jq '.groups | length')" -eq 0 ]
}

# ── Per-line first-match invariant (kv summary) ──────────────────────────────

@test "summary kv: same key repeated on a single line counts only the first occurrence" {
  # Without the awk `break`, a line like `EventCode=A EventCode=B` would
  # emit BOTH "A" and "B" — making sum(group.count) > total and diverging
  # from samples/extract (which use `next`/`exit`). This test pins the
  # invariant: total == sum(group.count); duplicates within a line are
  # not double-counted.
  cat > "$BATS_TEST_TMPDIR/repeat.log" <<'EOF'
EventCode=A EventCode=B
EventCode=A
EventCode=C
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/repeat.log" \
    --format kv --key EventCode --mode summary
  [ "$status" -eq 0 ]
  total="$(echo "$output" | jq '.total')"
  sum="$(echo "$output" | jq '[.groups[].count] | add')"
  [ "$total" -eq 3 ]
  [ "$sum" -eq 3 ]
  # First-match-per-line: line 1 contributes A (not B); line 2 contributes A;
  # line 3 contributes C. Final groups: A=2, C=1, B absent.
  [ "$(echo "$output" | jq '.groups[] | select(.key == "A") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key == "C") | .count')" -eq 1 ]
  [ "$(echo "$output" | jq '[.groups[] | select(.key == "B")] | length')" -eq 0 ]
}

# ── Blank-line filtering across formats (total == sum of group counts) ────────

@test "summary kv: blank lines are filtered from total and group counts" {
  # Three real events + two blank lines. total must be 3, not 5.
  # Group counts must sum to 3.
  cat > "$BATS_TEST_TMPDIR/kv-blanks.log" <<'EOF'
EventCode=A

EventCode=B
EventCode=A

EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-blanks.log" \
    --format kv --key EventCode --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 3 ]
  sum="$(echo "$output" | jq '[.groups[].count] | add')"
  [ "$sum" -eq 3 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="A") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="B") | .count')" -eq 1 ]
}

@test "summary text: blank lines are filtered from 'all' count" {
  cat > "$BATS_TEST_TMPDIR/text-blanks.txt" <<'EOF'
line one

line two

line three
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/text-blanks.txt" \
    --format text --key ignored --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 3 ]
  [ "$(echo "$output" | jq '.groups[0].count')" -eq 3 ]
}

# ── kv summary: JSON-encoding safety for hostile key values ──────────────────

@test "summary kv: key value containing a double quote is JSON-encoded safely" {
  # Pre-fix: awk hand-built JSON like `{"key":"a"b","count":1}` — invalid,
  # downstream `--argjson` blew up. Post-fix: jq -Rsc encodes the value
  # as `"a\"b"` and the pipeline produces valid JSON.
  cat > "$BATS_TEST_TMPDIR/quoted.log" <<'EOF'
EventCode=a"b user=alice
EventCode=a"b user=bob
EventCode=plain user=carol
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/quoted.log" \
    --format kv --key EventCode --mode summary
  [ "$status" -eq 0 ]
  # Output must be valid JSON (jq parses without error)
  echo "$output" | jq -e . >/dev/null
  # The double-quoted key value survives round-trip.
  [ "$(echo "$output" | jq -r '.groups[] | select(.key == "a\"b") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq -r '.groups[] | select(.key == "plain") | .count')" -eq 1 ]
}

@test "summary kv: key value containing a backslash is JSON-encoded safely" {
  cat > "$BATS_TEST_TMPDIR/bs.log" <<'EOF'
Path=C:\Windows EventCode=4624
Path=C:\Windows EventCode=4624
Path=C:\Users EventCode=4624
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/bs.log" \
    --format kv --key Path --mode summary
  [ "$status" -eq 0 ]
  echo "$output" | jq -e . >/dev/null
  [ "$(echo "$output" | jq '.groups | length')" -eq 2 ]
}

@test "summary NDJSON: total == sum of group counts (invariant under blanks)" {
  cat > "$BATS_TEST_TMPDIR/nd-blanks.ndjson" <<'EOF'
{"k":"A"}

{"k":"B"}
{"k":"A"}

EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/nd-blanks.ndjson" \
    --format ndjson --key k --mode summary
  [ "$status" -eq 0 ]
  total="$(echo "$output" | jq '.total')"
  sum="$(echo "$output" | jq '[.groups[].count] | add')"
  [ "$total" -eq 3 ]
  [ "$sum" -eq 3 ]
}

# ── kv summary: tolerant whitespace splitting ────────────────────────────────
# Pre-fix the kv branch used `awk -F'[= ]'` which emits an empty field per
# extra delimiter, breaking the odd-index/even-index key/value pairing on
# inputs with multiple spaces, tabs, or leading whitespace. Post-fix uses
# `split($0, a, /[=[:space:]]+/)` after `sub(/^[[:space:]]+/, "")`.

@test "summary kv: multiple spaces between tokens still group correctly" {
  # Two spaces between every token. Pre-fix grouping broke (every other
  # field was empty), so EventCode wouldn't be found at the expected
  # odd index.
  printf 'EventCode=4624  user=alice\nEventCode=4625  user=bob\nEventCode=4624  user=carol\n' \
    > "$BATS_TEST_TMPDIR/kv-spaces.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-spaces.log" \
    --format kv --key EventCode --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 3 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="4624") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="4625") | .count')" -eq 1 ]
}

@test "summary kv: tab-separated tokens group correctly" {
  # Tabs in place of spaces. Pre-fix `[= ]` separator did not include \t,
  # so the entire `EventCode=4624\tuser=alice` was one field and the
  # field-position scan never matched.
  printf 'EventCode=4624\tuser=alice\nEventCode=4625\tuser=bob\n' \
    > "$BATS_TEST_TMPDIR/kv-tabs.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-tabs.log" \
    --format kv --key EventCode --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="4624") | .count')" -eq 1 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="4625") | .count')" -eq 1 ]
}

@test "summary kv: leading whitespace on lines does not desync key/value pairs" {
  # Lines start with two spaces of indent. Pre-fix this either preserved
  # the empty leading field (regex FS) or broke pairing; post-fix sub()
  # strips it before split().
  printf '  EventCode=4624 user=alice\n  EventCode=4624 user=bob\n' \
    > "$BATS_TEST_TMPDIR/kv-indent.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-indent.log" \
    --format kv --key EventCode --mode summary
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.total')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="4624") | .count')" -eq 2 ]
}

# ── Explicit --format json on an NDJSON file ─────────────────────────────────
# CloudTrail datasets ship as either a single {Records:[...]} document or as
# NDJSON (one event per line); the skill's format guidance says json-mode
# handles both. Pre-fix it did not: the json summary branch runs
# `jq <filter> "$DATASET"`, which streams each NDJSON line as a separate value,
# producing multi-value $total/$groups_json that then blew up the final
# `jq --argjson` ("invalid JSON text passed to --argjson", exit 2). Post-fix
# the dispatcher reclassifies json→ndjson when the bytes are actually NDJSON,
# so the call succeeds and reports format=ndjson with correct counts.

@test "summary JSON flag on NDJSON: reclassifies to ndjson and counts groups" {
  cat > "$BATS_TEST_TMPDIR/ct.ndjson" <<'EOF'
{"eventName":"DeleteTrail"}
{"eventName":"UpdateTrail"}
{"eventName":"UpdateTrail"}
{"eventName":"StopLogging"}
{"eventName":"CreateAccessKey"}
{"eventName":"DeleteTrail"}
{"eventName":"PutEventSelectors"}
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/ct.ndjson" \
    --format json --key eventName --mode summary
  [ "$status" -eq 0 ]
  echo "$output" | jq -e . >/dev/null
  [ "$(echo "$output" | jq -r '.format')" = "ndjson" ]
  [ "$(echo "$output" | jq '.total')" -eq 7 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="DeleteTrail") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="UpdateTrail") | .count')" -eq 2 ]
  [ "$(echo "$output" | jq '.groups[] | select(.key=="CreateAccessKey") | .count')" -eq 1 ]
}
