#!/usr/bin/env bats
#
# diff-against-master.sh tests.
#
# The script is the report-time visualization aid (SKILL.md step 13): it
# canonicalizes a master event and a generated event and emits a unified diff so
# a human can eyeball fidelity beyond compare-fidelity.sh's pass/warn/fail
# verdict. These tests pin: formatting is canonicalized away (indentation, JSON
# key order), real value differences (including gen.* environmental churn) are
# shown flat, only the first event of a burst is diffed, and misuse hard-fails.

bats_require_minimum_version 1.5.0
load helpers

setup() { scenario_authoring_setup; }

diffm() {
  "$SCRIPTS_DIR/diff-against-master.sh" "$@"
}

# ── XML: identical after canonicalization ─────────────────────────────────────

@test "xml: identical content (differing indentation only) → no differences, exit 0" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>1</EventID></System><EventData><Data Name="Image">C:\a\procdump.exe</Data></EventData></Event>
EOF
  # Same content, wildly different whitespace/layout.
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<?xml version="1.0"?>
<Event xmlns="http://x">
    <System>
        <EventID>1</EventID>
    </System>
    <EventData>
        <Data Name="Image">C:\a\procdump.exe</Data>
    </EventData>
</Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

# ── XML: gen.* environmental churn is shown flat ──────────────────────────────

@test "xml: differing gen.* fields (TimeCreated, EventRecordID) shown as diff lines" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>1</EventID><TimeCreated SystemTime="2024-03-01T12:00:00Z"/><EventRecordID>10</EventRecordID></System><EventData><Data Name="Image">C:\a\procdump.exe</Data></EventData></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>1</EventID><TimeCreated SystemTime="2026-07-05T09:14:22Z"/><EventRecordID>7788</EventRecordID></System><EventData><Data Name="Image">C:\a\procdump.exe</Data></EventData></Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  # The two environmental values appear on -/+ lines; the identical Image line does not.
  [[ "$output" == *"-"*"2024-03-01T12:00:00Z"* ]]
  [[ "$output" == *"+"*"2026-07-05T09:14:22Z"* ]]
  [[ "$output" == *"7788"* ]]
  echo "$output" | grep -E '^[-+].*procdump\.exe' && return 1 || true
}

# ── XML: multi-event burst — only the first event is diffed, with a note ───────

@test "xml: multi-event generated burst → note printed, first event diffed" {
  # Master is a single 4720 event; generated is a 4720 + 4732 burst (sibling roots).
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>4720</EventID></System><EventData><Data Name="TargetUserName">svc</Data></EventData></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<?xml version="1.0"?>
<Event xmlns="http://x"><System><EventID>4720</EventID></System><EventData><Data Name="TargetUserName">svc</Data></EventData></Event>
<?xml version="1.0"?>
<Event xmlns="http://x"><System><EventID>4732</EventID></System><EventData><Data Name="TargetUserName">Administrators</Data></EventData></Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"generated render produced 2 events"* ]]
  # First event matches the master → no value diff; the second event (4732) is
  # never reached, so it must not appear in the output.
  [[ "$output" != *"4732"* ]]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "xml: concatenated burst (roots on one line) → counted by occurrence, not line" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>4720</EventID></System><EventData><Data Name="TargetUserName">svc</Data></EventData></Event>
EOF
  # Two <Event> roots with no newline between them: a line-based count would report
  # 1 and skip the burst note; occurrence counting must report 2.
  printf '%s%s\n' \
    '<Event xmlns="http://x"><System><EventID>4720</EventID></System><EventData><Data Name="TargetUserName">svc</Data></EventData></Event>' \
    '<Event xmlns="http://x"><System><EventID>4732</EventID></System><EventData><Data Name="TargetUserName">Administrators</Data></EventData></Event>' \
    > "$BATS_TEST_TMPDIR/g.xml"
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"generated render produced 2 events"* ]]
  [[ "$output" != *"4732"* ]]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

# ── JSON: identical + key-order canonicalization ──────────────────────────────

@test "json: identical values in different key order → canonicalized to no differences" {
  printf '{"eventName":"DeleteTrail","eventTime":"2024-01-01T00:00:00Z","eventVersion":"1.08"}\n' \
    > "$BATS_TEST_TMPDIR/m.json"
  printf '{"eventVersion":"1.08","eventName":"DeleteTrail","eventTime":"2024-01-01T00:00:00Z"}\n' \
    > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.json" --generated "$BATS_TEST_TMPDIR/g.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "json: differing gen.* fields shown, unrelated fields stay as context" {
  printf '{"eventName":"DeleteTrail","eventTime":"2024-01-01T00:00:00Z","sourceIPAddress":"10.0.0.1"}\n' \
    > "$BATS_TEST_TMPDIR/m.json"
  printf '{"eventName":"DeleteTrail","eventTime":"2026-07-05T09:00:00Z","sourceIPAddress":"203.0.113.9"}\n' \
    > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.json" --generated "$BATS_TEST_TMPDIR/g.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"10.0.0.1"* ]]
  [[ "$output" == *"203.0.113.9"* ]]
  # eventName is identical on both sides → must not be a -/+ line.
  echo "$output" | grep -E '^[-+].*DeleteTrail' && return 1 || true
}

# ── JSON: first-record selection (NDJSON, Records-wrapped, array) ─────────────

@test "json: NDJSON master (multi-record) → first record used for the diff" {
  cat > "$BATS_TEST_TMPDIR/m.ndjson" <<'EOF'
{"eventName":"GetUser","errorCode":"AccessDenied"}
{"eventName":"ListUsers","errorCode":"AccessDenied"}
EOF
  printf '{"eventName":"GetUser","errorCode":"AccessDenied"}\n' > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.ndjson" --generated "$BATS_TEST_TMPDIR/g.json"
  [ "$status" -eq 0 ]
  # First master record equals the generated one; ListUsers (record 2) is ignored.
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
  [[ "$output" != *"ListUsers"* ]]
}

@test "json: Records-wrapped master → first record compared" {
  printf '{"Records":[{"eventName":"GetUser"},{"eventName":"ListUsers"}]}\n' > "$BATS_TEST_TMPDIR/m.json"
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.json" --generated "$BATS_TEST_TMPDIR/g.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

# ── JSON: multi-event burst count note (array + NDJSON, streamed) ──────────────

@test "json: array-wrapped generated burst → note reports the full element count" {
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/m.json"
  printf '[{"eventName":"GetUser"},{"eventName":"ListUsers"},{"eventName":"DeleteUser"}]\n' \
    > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.json" --generated "$BATS_TEST_TMPDIR/g.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"generated render produced 3 events"* ]]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "json: NDJSON generated burst → note counts every record without slurping" {
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/m.json"
  cat > "$BATS_TEST_TMPDIR/g.ndjson" <<'EOF'
{"eventName":"GetUser"}
{"eventName":"ListUsers"}
{"eventName":"DeleteUser"}
{"eventName":"CreateUser"}
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.json" --generated "$BATS_TEST_TMPDIR/g.ndjson"
  [ "$status" -eq 0 ]
  [[ "$output" == *"generated render produced 4 events"* ]]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

# ── KV/admon: canonicalization + burst count ─────────────────────────────────

@test "kv: timestamp, section layout, ordering, and CRLF canonicalize away" {
  printf '%s\n' \
    '11/24/2023 05:09:11.485' \
    'dcName=dc1' \
    'Names:' \
    $'\tdisplayName=MSI\r' \
    'Object Details:' \
    $'\tobjectClass=top|container|groupPolicyContainer\r' > "$BATS_TEST_TMPDIR/m.log"
  cat > "$BATS_TEST_TMPDIR/g.log" <<'EOF'
dcName=dc1
Object Details:
	objectClass=top|container|groupPolicyContainer
Names:
	displayName=MSI
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.log" --generated "$BATS_TEST_TMPDIR/g.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "kv: auto-detect recognizes a BOM-prefixed first dcName" {
  printf '\357\273\277dcName=dc1\nNames:\n\tdisplayName=MSI\n' > "$BATS_TEST_TMPDIR/m.log"
  printf 'dcName=dc1\nNames:\n\tdisplayName=MSI\n' > "$BATS_TEST_TMPDIR/g.log"
  run diffm --master "$BATS_TEST_TMPDIR/m.log" --generated "$BATS_TEST_TMPDIR/g.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "kv: space indentation and documented timestamp preambles canonicalize away" {
  printf '2/1/10\n3:11:09.074 PM\n02/01/2010 15:11:09.0748\ndcName=dc1\nNames:\n  displayName=MSI\n' \
    > "$BATS_TEST_TMPDIR/m.log"
  printf 'dcName=dc1\nNames:\n\tdisplayName=MSI\n' > "$BATS_TEST_TMPDIR/g.log"
  run diffm --master "$BATS_TEST_TMPDIR/m.log" --generated "$BATS_TEST_TMPDIR/g.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "kv: changed explicit field appears in the diff" {
  printf 'dcName=dc1\nNames:\n\tdisplayName=Master\n' > "$BATS_TEST_TMPDIR/m.log"
  printf 'dcName=dc1\nNames:\n\tdisplayName=Generated\n' > "$BATS_TEST_TMPDIR/g.log"
  run diffm --master "$BATS_TEST_TMPDIR/m.log" --generated "$BATS_TEST_TMPDIR/g.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"-displayName=Master"* ]]
  [[ "$output" == *"+displayName=Generated"* ]]
}

@test "kv: repeated dcName burst prints count and diffs only the first event" {
  printf 'dcName=dc1\nEvent Details:\n\tuSNChanged=1\n' > "$BATS_TEST_TMPDIR/m.log"
  printf 'dcName=dc1\nEvent Details:\n\tuSNChanged=1\ndcName=dc1\nEvent Details:\n\tuSNChanged=2\n' \
    > "$BATS_TEST_TMPDIR/g.log"
  run diffm --master "$BATS_TEST_TMPDIR/m.log" --generated "$BATS_TEST_TMPDIR/g.log"
  [ "$status" -eq 0 ]
  [[ "$output" == *"generated render produced 2 events"* ]]
  [[ "$output" != *"uSNChanged=2"* ]]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "kv: parse errors use the diff script contract" {
  printf 'dcName=dc1\nNames:\n\tdisplayName=a\n\tdisplayName=b\n' > "$BATS_TEST_TMPDIR/bad.log"
  run diffm --master "$BATS_TEST_TMPDIR/bad.log" --generated "$BATS_TEST_TMPDIR/bad.log" --format kv
  [ "$status" -eq 1 ]
  [[ "$output" == "diff-against-master.sh: cannot parse ActiveDirectory admon KV"* ]]
  [[ "$output" == *"duplicate non-empty field"* ]]
}

@test "auto: generic key=value receives an admon-specific diff diagnostic" {
  printf 'EventCode=4624 user=alice\n' > "$BATS_TEST_TMPDIR/generic.log"
  run diffm --master "$BATS_TEST_TMPDIR/generic.log" --generated "$BATS_TEST_TMPDIR/generic.log"
  [ "$status" -eq 2 ]
  [[ "$output" == "diff-against-master.sh: generic key=value input is not supported"* ]]
}

# ── Guards: format mismatch, usage, parse errors ──────────────────────────────

@test "auto: XML master + JSON generated → exit 2 (likely wrong file paths)" {
  printf '<Event><System><EventID>1</EventID></System></Event>\n' > "$BATS_TEST_TMPDIR/m.xml"
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.json"
  [ "$status" -eq 2 ]
  [[ "$output" == *"format"* ]]
  [[ "$output" == *"differ"* ]]
}

@test "usage: --master required" {
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/g.json"
  run diffm --generated "$BATS_TEST_TMPDIR/g.json"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--master required"* ]]
}

@test "usage: --generated required" {
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/m.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.json"
  [ "$status" -eq 2 ]
  [[ "$output" == *"--generated required"* ]]
}

@test "usage: master not found surfaces the path" {
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master /tmp/does-not-exist-diff-master --generated "$BATS_TEST_TMPDIR/g.json"
  [ "$status" -eq 2 ]
  [[ "$output" == *"master not found: /tmp/does-not-exist-diff-master"* ]]
}

@test "usage: unknown flag rejected with exit 2" {
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/m.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.json" --bogus x
  [ "$status" -eq 2 ]
  [[ "$output" == *"unknown flag: --bogus"* ]]
}

@test "usage: unsupported --format value → exit 2" {
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/m.json"
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.json" --generated "$BATS_TEST_TMPDIR/g.json" --format yaml
  [ "$status" -eq 2 ]
  [[ "$output" == *"unsupported format"* ]]
}

@test "json: unparseable master → non-zero with a clear message" {
  printf 'this is not json\n' > "$BATS_TEST_TMPDIR/m.json"
  printf '{"eventName":"GetUser"}\n' > "$BATS_TEST_TMPDIR/g.json"
  run diffm --master "$BATS_TEST_TMPDIR/m.json" --generated "$BATS_TEST_TMPDIR/g.json" --format json
  [ "$status" -ne 0 ]
  [[ "$output" == *"cannot parse"* ]] || [[ "$output" == *"non-empty event object"* ]]
}
