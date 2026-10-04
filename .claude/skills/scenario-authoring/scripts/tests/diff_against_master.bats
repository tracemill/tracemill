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

# ── XML: Windows element/attribute canonicalization ───────────────────────────

changed_lines() {
  printf '%s\n' "$1" | grep -E '^[-+]' | grep -vE '^(---|\+\+\+) '
}

@test "xml: System children and Event children in a different order → no differences" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns='http://x'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>11</EventID><Version>2</Version><Level>4</Level><Task>11</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2021-07-01T16:20:47Z'/><EventRecordID>10</EventRecordID><Correlation/><Execution ProcessID='2100' ThreadID='3092'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>host-a</Computer><Security UserID='S-1-5-18'/><ZExtra>z</ZExtra><AExtra>a</AExtra></System><EventData><Data Name='RuleName'>-</Data><Data Name='Image'>C:\a\spoolsv.exe</Data></EventData></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns='http://x'>
  <EventData>
    <Data Name='RuleName'>-</Data>
    <Data Name='Image'>C:\a\spoolsv.exe</Data>
  </EventData>
  <System>
    <AExtra>a</AExtra>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>host-a</Computer>
    <Correlation/>
    <EventID>11</EventID>
    <EventRecordID>10</EventRecordID>
    <Execution ProcessID='2100' ThreadID='3092'/>
    <Keywords>0x8000000000000000</Keywords>
    <Level>4</Level>
    <Opcode>0</Opcode>
    <Provider Name='Microsoft-Windows-Sysmon'/>
    <Security UserID='S-1-5-18'/>
    <Task>11</Task>
    <TimeCreated SystemTime='2021-07-01T16:20:47Z'/>
    <Version>2</Version>
    <ZExtra>z</ZExtra>
  </System>
</Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "xml: canonical form puts System first in schema order, then other children in document order" {
  # Every value differs so every element surfaces as a - line in document order.
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns="http://x"><EventData><Data Name="A">1</Data></EventData><System><Computer>h1</Computer><ZExtra>z1</ZExtra><EventID>1</EventID><AExtra>a1</AExtra><Provider Name="p1"/></System></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<Event xmlns="http://x"><EventData><Data Name="A">2</Data></EventData><System><Computer>h2</Computer><ZExtra>z2</ZExtra><EventID>2</EventID><AExtra>a2</AExtra><Provider Name="p2"/></System></Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  local tags
  tags="$(changed_lines "$output" | grep -E '^-' | sed -E 's/^- *<([A-Za-z]+).*/\1/' | tr '\n' ' ')"
  [ "$tags" = "Provider EventID Computer AExtra ZExtra Data " ]
}

@test "xml: reordered EventData <Data> entries are still shown" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>11</EventID></System><EventData><Data Name="Image">a</Data><Data Name="TargetFilename">b</Data></EventData></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>11</EventID></System><EventData><Data Name="TargetFilename">b</Data><Data Name="Image">a</Data></EventData></Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [[ "$output" != *"no differences after formatting canonicalization"* ]]
  [ "$(changed_lines "$output" | wc -l | tr -d ' ')" -eq 2 ]
}

@test "xml: attribute order and quote style → no differences" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns='http://x'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><Execution ProcessID='2100' ThreadID='3092'/></System></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<Event xmlns="http://x">
  <System>
    <Execution ThreadID="3092" ProcessID="2100"></Execution>
    <Provider Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" Name="Microsoft-Windows-Sysmon"/>
  </System>
</Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "xml: empty-element forms and the master's <Correlation>null</Correlation> artifact → no differences" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>11</EventID><Correlation>null</Correlation><Security UserID="S-1-5-18"></Security></System><EventData><Data Name="RuleName"/></EventData></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>11</EventID><Correlation/><Security UserID="S-1-5-18"/></System><EventData><Data Name="RuleName"></Data></EventData></Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"no differences after formatting canonicalization"* ]]
}

@test "xml: a literal null Correlation in the generated render is still shown" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>11</EventID><Correlation/></System></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<Event xmlns="http://x"><System><EventID>11</EventID><Correlation>null</Correlation></System></Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"+"*"<Correlation>null</Correlation>"* ]]
}

@test "xml: reordered inputs → only the real value differences remain" {
  cat > "$BATS_TEST_TMPDIR/m.xml" <<'EOF'
<Event xmlns='http://x'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{G}'/><EventID>11</EventID><EventRecordID>7997763</EventRecordID><Correlation/><Computer>win-dc-128.attackrange.local</Computer></System><EventData><Data Name='RuleName'>DLL</Data><Data Name='Image'>C:\Windows\System32\spoolsv.exe</Data><Data Name='TargetFilename'>C:\Windows\System32\spool\drivers\x64\3\New\evil.dll</Data></EventData></Event>
EOF
  cat > "$BATS_TEST_TMPDIR/g.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns='http://x'>
  <EventData>
    <Data Name='RuleName'>-</Data>
    <Data Name='Image'>C:\Windows\System32\spoolsv.exe</Data>
    <Data Name='TargetFilename'>C:\Windows\System32\spool\drivers\x64\3\New\evil.dll</Data>
  </EventData>
  <System>
    <Computer>SCCM09.corp.local</Computer>
    <Correlation/>
    <EventID>11</EventID>
    <EventRecordID>5418313</EventRecordID>
    <Provider Guid='{G}' Name='Microsoft-Windows-Sysmon'/>
  </System>
</Event>
EOF
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  local changed
  changed="$(changed_lines "$output")"
  [ "$(printf '%s\n' "$changed" | wc -l | tr -d ' ')" -eq 6 ]
  [[ "$changed" == *"-"*"<EventRecordID>7997763</EventRecordID>"* ]]
  [[ "$changed" == *"+"*"<EventRecordID>5418313</EventRecordID>"* ]]
  [[ "$changed" == *"-"*"<Computer>win-dc-128.attackrange.local</Computer>"* ]]
  [[ "$changed" == *"+"*"<Computer>SCCM09.corp.local</Computer>"* ]]
  [[ "$changed" == *"-"*'<Data Name="RuleName">DLL</Data>'* ]]
  [[ "$changed" == *"+"*'<Data Name="RuleName">-</Data>'* ]]
}

@test "xml: non-Event root → attributes sorted, child order kept, no Windows elements invented" {
  printf '<Root b="2" a="1"><Z>1</Z><A>1</A></Root>\n' > "$BATS_TEST_TMPDIR/m.xml"
  printf "<Root a='1' b='2'><Z>1</Z><A>2</A></Root>\n" > "$BATS_TEST_TMPDIR/g.xml"
  run diffm --master "$BATS_TEST_TMPDIR/m.xml" --generated "$BATS_TEST_TMPDIR/g.xml"
  [ "$status" -eq 0 ]
  [ "$(changed_lines "$output" | wc -l | tr -d ' ')" -eq 2 ]
  [[ "$output" == *'-  <A>1</A>'* ]]
  [[ "$output" == *'+  <A>2</A>'* ]]
  [[ "$output" != *"Event"* ]]
  [[ "$output" != *"System"* ]]
  [[ "$output" != *"null"* ]]
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
