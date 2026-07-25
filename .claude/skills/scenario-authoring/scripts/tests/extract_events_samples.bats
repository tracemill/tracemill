#!/usr/bin/env bats

load helpers

setup() {
  scenario_authoring_setup
  export OUT_DIR="$BATS_TEST_TMPDIR/samples"
}

@test "samples XML: one file per distinct EventID" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --format xml --key "System/EventID" --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/1.xml" ]
  [ -f "$OUT_DIR/10.xml" ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
  # Rendered XML files are valid <Event> blocks with the matching EID.
  grep -q '<EventID>1</EventID>' "$OUT_DIR/1.xml"
  grep -q '<EventID>10</EventID>' "$OUT_DIR/10.xml"
}

@test "samples JSON: one file per distinct eventName" {
  run extract_events --dataset "$FIXTURES/dataset-cloudtrail.json" \
    --format json --key eventName --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/CreateAccessKey.json" ]
  [ -f "$OUT_DIR/DeleteTrail.json" ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
}

@test "samples NDJSON: nested dotted-path key (regression: subshell loop)" {
  cat > "$BATS_TEST_TMPDIR/nested.ndjson" <<'EOF'
{"userIdentity":{"userName":"alice"},"region":"us-east-1"}
{"userIdentity":{"userName":"bob"},"region":"us-west-2"}
{"userIdentity":{"userName":"alice"},"region":"eu-west-1"}
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/nested.ndjson" \
    --format ndjson --key "userIdentity.userName" --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  # Both sample files must exist, and the JSON results array must NOT be
  # empty (previous regression: pipeline-into-while ran in subshell and
  # lost the results accumulator).
  [ -f "$OUT_DIR/alice.ndjson" ]
  [ -f "$OUT_DIR/bob.ndjson" ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
}

@test "samples kv: one file per distinct key value" {
  cat > "$BATS_TEST_TMPDIR/kv.log" <<'EOF'
EventCode=4624 user=alice
EventCode=4625 user=bob
EventCode=4624 user=carol
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv.log" \
    --format kv --key EventCode --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/4624.log" ]
  [ -f "$OUT_DIR/4625.log" ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
}

@test "samples admon: first complete record per value is written" {
  printf 'dcName=dc1\nNames:   \n\tname=Alice\ndcName=dc2\nNames:\n\tname=Bob\ndcName=dc3\nNames:\n\tname=Alice\n' \
    > "$BATS_TEST_TMPDIR/admon.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/admon.log" \
    --format admon --key name --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
  grep -q '^dcName=dc1$' "$OUT_DIR/Alice.log"
  grep -q '^Names:   $' "$OUT_DIR/Alice.log"
  ! grep -q '^dcName=dc3$' "$OUT_DIR/Alice.log"
}

@test "samples admon: extracted payload excludes timestamp and sentinel framing" {
  printf '11/24/2023 05:09:11.485\ndcName=dc1\nNames:\n\tname=Alice\n---splunk-admon-end-of-event---\ndcName=dc2\nNames:\n\tname=Bob\n' \
    > "$BATS_TEST_TMPDIR/admon.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/admon.log" \
    --format admon --key name --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  grep -q '^dcName=dc1$' "$OUT_DIR/Alice.log"
  ! grep -q '^11/24/2023 ' "$OUT_DIR/Alice.log"
  ! grep -q '^---splunk-admon-end-of-event---$' "$OUT_DIR/Alice.log"
}

@test "samples admon: parse failures are attributed to the helper" {
  printf 'Names:\n' > "$BATS_TEST_TMPDIR/bad.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/bad.log" \
    --format admon --key name --mode samples --out "$OUT_DIR"
  [ "$status" -eq 1 ]
  [[ "$output" == "_extract-events-samples.sh: cannot parse ActiveDirectory admon KV"* ]]
  [[ "$output" == *"section header before record-start dcName"* ]]
}

@test "samples text: single 'all' sample with first non-empty line" {
  printf '\nline one\nline two\n' > "$BATS_TEST_TMPDIR/plain.txt"
  run extract_events --dataset "$BATS_TEST_TMPDIR/plain.txt" \
    --format text --key anything --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/all.log" ]
  [ "$(cat "$OUT_DIR/all.log")" = "line one" ]
  [ "$(echo "$output" | jq 'length')" -eq 1 ]
}

@test "--key required for samples mode" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --mode samples --out "$OUT_DIR"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--key required"* ]]
}

@test "--out required for samples mode" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --format xml --key "System/EventID" --mode samples
  [ "$status" -eq 2 ]
  [[ "$output" == *"--out required"* ]]
}

# ── safe_key: collision avoidance + clean-key preservation ──────────────────

@test "samples NDJSON: keys that would sanitise to the same name get unique sample paths" {
  # Both "a/b" and "a?b" sanitise to "a_b" under tr -c 'A-Za-z0-9._-' '_'.
  # Without disambiguation the second event would be silently skipped by
  # the `[[ ! -f "$out" ]]` guard. With the cksum suffix, two distinct
  # files exist and both records appear in the results array.
  cat > "$BATS_TEST_TMPDIR/collide.ndjson" <<'EOF'
{"k":"a/b"}
{"k":"a?b"}
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/collide.ndjson" \
    --format ndjson --key k --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  count="$(ls "$OUT_DIR" | wc -l | tr -d ' ')"
  [ "$count" -eq 2 ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
  echo "$output" | jq -e '.[] | select(.key == "a/b")' >/dev/null
  echo "$output" | jq -e '.[] | select(.key == "a?b")' >/dev/null
}

@test "samples JSON: keys with collision-prone characters get hash-suffixed paths" {
  cat > "$BATS_TEST_TMPDIR/collide.json" <<'EOF'
[
  {"path":"foo/bar"},
  {"path":"foo?bar"}
]
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/collide.json" \
    --format json --key path --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
  # Both sample files start with the sanitised stem "foo_bar" but differ
  # by the appended hash (`foo_bar-<hash>.json`).
  count="$(ls "$OUT_DIR"/foo_bar-*.json 2>/dev/null | wc -l | tr -d ' ')"
  [ "$count" -eq 2 ]
}

@test "samples JSON: clean keys keep the simple unhashed filename (no needless suffix)" {
  # When sanitisation is a no-op, the filename should NOT carry a hash
  # suffix — the readable name is the contract.
  cat > "$BATS_TEST_TMPDIR/clean.json" <<'EOF'
[{"k":"alice"},{"k":"bob"}]
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/clean.json" \
    --format json --key k --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/alice.json" ]
  [ -f "$OUT_DIR/bob.json" ]
  # Confirm no hash-suffixed variants leaked alongside the simple names.
  ! compgen -G "$OUT_DIR/alice-*.json" >/dev/null
  ! compgen -G "$OUT_DIR/bob-*.json" >/dev/null
}

@test "samples XML: numeric EID keys (no special chars) keep simple filenames" {
  # Regression check: existing fixture's EIDs (1, 10) must continue to
  # produce 1.xml / 10.xml, not 1-<hash>.xml etc.
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --format xml --key "System/EventID" --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/1.xml" ]
  [ -f "$OUT_DIR/10.xml" ]
  ! compgen -G "$OUT_DIR/1-*.xml" >/dev/null
  ! compgen -G "$OUT_DIR/10-*.xml" >/dev/null
}

# ── kv samples behaviour + Bash 3.2 portability ──────────────────────────────

@test "samples kv: groups by distinct value, writes first matching line per group" {
  # Functional check that the post-fix sort-u + per-value awk-scan
  # implementation produces the same output as the pre-fix associative-
  # array implementation.
  cat > "$BATS_TEST_TMPDIR/kv.log" <<'EOF'
EventCode=4624 user=alice
EventCode=4625 user=bob
EventCode=4624 user=carol
EventCode=4625 user=dan
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv.log" \
    --format kv --key EventCode --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/4624.log" ]
  [ -f "$OUT_DIR/4625.log" ]
  # First-line semantics: the user written should be alice (first 4624)
  # and bob (first 4625), not carol/dan.
  grep -q 'user=alice' "$OUT_DIR/4624.log"
  grep -q 'user=bob'   "$OUT_DIR/4625.log"
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
}

@test "samples script does not use Bash-4-only 'declare -A' (macOS Bash 3.2 portability)" {
  # The kv samples branch previously used `declare -A kv_seen=()`, which
  # silently fails on macOS where /usr/bin/bash is 3.2. Static check: the
  # source must contain no associative-array declarations.
  # The regex requires the line to BE a declaration (optional leading
  # whitespace, then `declare -A <name>=`), not just to mention the
  # phrase in a comment.
  ! grep -Eq '^[[:space:]]*declare -A [A-Za-z_]+=' \
      "$SCRIPTS_DIR/_extract-events-samples.sh"
}

@test "samples script does not use Bash-4-only 'declare -A' (entire script kit)" {
  # Same check across all handler scripts so future additions don't
  # quietly re-introduce a Bash 3.2 incompatibility.
  ! grep -REq '^[[:space:]]*declare -A [A-Za-z_]+=' \
      "$SCRIPTS_DIR"/*.sh
}

# ── kv samples: tolerant whitespace splitting ────────────────────────────────
# Same root cause as the summary kv tests: pre-fix `awk -F'[= ]'` mis-paired
# fields when delimiters repeated.

@test "samples kv: multiple spaces between tokens still produce one file per distinct value" {
  printf 'EventCode=4624  user=alice\nEventCode=4625  user=bob\nEventCode=4624  user=carol\n' \
    > "$BATS_TEST_TMPDIR/kv-spaces.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-spaces.log" \
    --format kv --key EventCode --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/4624.log" ]
  [ -f "$OUT_DIR/4625.log" ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
  # First 4624 is alice, not carol — the first-line-per-group invariant
  # must survive the new splitter.
  grep -q 'user=alice' "$OUT_DIR/4624.log"
  grep -q 'user=bob'   "$OUT_DIR/4625.log"
}

@test "samples kv: tab-separated tokens still produce one file per distinct value" {
  printf 'EventCode=4624\tuser=alice\nEventCode=4625\tuser=bob\n' \
    > "$BATS_TEST_TMPDIR/kv-tabs.log"
  run extract_events --dataset "$BATS_TEST_TMPDIR/kv-tabs.log" \
    --format kv --key EventCode --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ -f "$OUT_DIR/4624.log" ]
  [ -f "$OUT_DIR/4625.log" ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
}

# ── safe_key: long all-safe stems are truncated and hash-suffixed ────────────

@test "samples JSON: very long all-safe key value produces a truncated, hash-suffixed filename" {
  # Build a 300-char value of [A-Za-z0-9._-] — pre-fix safe_key was a no-op
  # for this input (no sanitisation needed) and the resulting `<value>.json`
  # path would exceed NAME_MAX (255 on most filesystems), failing the
  # `> "$out"` redirect at runtime. Post-fix, stems > 200 bytes are
  # truncated and a cksum-hex suffix is appended for uniqueness.
  long_key="$(printf 'a%.0s' {1..300})"
  cat > "$BATS_TEST_TMPDIR/long.json" <<EOF
[{"k":"$long_key"}]
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/long.json" \
    --format json --key k --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq 'length')" -eq 1 ]
  # Exactly one file written, with stem <= 200 bytes (cap from safe_key)
  # plus ".json" extension.
  written="$(ls "$OUT_DIR")"
  stem="${written%.json}"
  [ "${#stem}" -le 200 ]
  # The truncated form must carry a hash suffix (-<hex>) so future
  # values that share the truncated prefix don't collide silently.
  [[ "$stem" == *-* ]]
}

@test "samples JSON: two long all-safe keys sharing a prefix get distinct truncated filenames" {
  # Stems differ only in characters past the 200-byte truncation point.
  # Without the always-hash-when-truncated rule, both would land on the
  # same filename and the second sample would silently overwrite the
  # first (xml/json branches) or be skipped (ndjson branch).
  prefix="$(printf 'p%.0s' {1..210})"
  cat > "$BATS_TEST_TMPDIR/long2.json" <<EOF
[
  {"k":"${prefix}AAA"},
  {"k":"${prefix}BBB"}
]
EOF
  run extract_events --dataset "$BATS_TEST_TMPDIR/long2.json" \
    --format json --key k --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq 'length')" -eq 2 ]
  count="$(ls "$OUT_DIR" | wc -l | tr -d ' ')"
  [ "$count" -eq 2 ]
}

@test "samples NDJSON: very long all-safe key value writes successfully (no NAME_MAX failure)" {
  # Direct regression check: pre-fix this would fail at `> "$out"` when
  # the OS rejected the over-long path with ENAMETOOLONG.
  long_key="$(printf 'x%.0s' {1..300})"
  printf '{"k":"%s"}\n' "$long_key" > "$BATS_TEST_TMPDIR/long.ndjson"
  run extract_events --dataset "$BATS_TEST_TMPDIR/long.ndjson" \
    --format ndjson --key k --mode samples --out "$OUT_DIR"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq 'length')" -eq 1 ]
  # One file with name <= 200 stem + ".ndjson" extension.
  written="$(ls "$OUT_DIR")"
  [ -n "$written" ]
  stem="${written%.ndjson}"
  [ "${#stem}" -le 200 ]
}
