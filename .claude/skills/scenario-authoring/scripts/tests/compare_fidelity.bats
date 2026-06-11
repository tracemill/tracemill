#!/usr/bin/env bats
#
# compare-fidelity.sh tests.
#
# Pre-fix this script only handled Windows EventLog XML — `yq -p xml` was
# hardcoded and any JSON input failed with `invalid XML`. CloudTrail (and any
# other JSON-shaped surface) could not be fidelity-checked
# at all, so Phase 1 step 14 silently fell back to a manual diff. These tests
# pin the JSON / NDJSON support and keep the original XML path covered as a
# regression net.

load helpers

setup() { scenario_authoring_setup; }

compare() {
  "$SCRIPTS_DIR/compare-fidelity.sh" "$@"
}

# Minimal Sysmon EventID 22 (DnsQuery) — used as a structural baseline so the
# XML branch keeps producing the dot-path shape the verdict logic depends on.
write_xml_master() {
  cat > "$1" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>22</EventID>
    <Provider Name="Microsoft-Windows-Sysmon"/>
  </System>
  <EventData>
    <Data Name="QueryName">evil.example.com</Data>
    <Data Name="Image">C:\\Windows\\System32\\nslookup.exe</Data>
  </EventData>
</Event>
EOF
}

write_xml_generated_match() {
  cat > "$1" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>22</EventID>
    <Provider Name="Microsoft-Windows-Sysmon"/>
  </System>
  <EventData>
    <Data Name="QueryName">evil.example.com</Data>
    <Data Name="Image">C:\\Windows\\System32\\nslookup.exe</Data>
  </EventData>
</Event>
EOF
}

# CloudTrail — the surface that motivated this change.
write_json_master() {
  cat > "$1" <<'EOF'
{
  "eventVersion": "1.08",
  "eventSource": "iam.amazonaws.com",
  "eventName": "GetUser",
  "errorCode": "AccessDenied",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alice"
  },
  "tlsDetails": {
    "tlsVersion": "TLSv1.2"
  }
}
EOF
}

write_json_generated_match() {
  cat > "$1" <<'EOF'
{
  "eventVersion": "1.08",
  "eventSource": "iam.amazonaws.com",
  "eventName": "GetUser",
  "errorCode": "AccessDenied",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alice"
  },
  "tlsDetails": {
    "tlsVersion": "TLSv1.2"
  }
}
EOF
}

# ── Regression: XML path unchanged ────────────────────────────────────────────

@test "xml: identical master and generated → pass, coverage 100%" {
  write_xml_master       "$BATS_TEST_TMPDIR/m.xml"
  write_xml_generated_match "$BATS_TEST_TMPDIR/g.xml"
  run compare --master "$BATS_TEST_TMPDIR/m.xml" \
              --generated "$BATS_TEST_TMPDIR/g.xml" \
              --load-bearing "EventData.QueryName,System.EventID"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "pass" ]
  [ "$(echo "$output" | jq -r '.load_bearing_match')" = "true" ]
  [ "$(echo "$output" | jq '.coverage_pct')" = "100" ]
}

# ── JSON: identical inputs ────────────────────────────────────────────────────

@test "json: identical master and generated → pass, coverage 100%" {
  write_json_master           "$BATS_TEST_TMPDIR/m.json"
  write_json_generated_match  "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing "eventName,errorCode,userIdentity.type"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "pass" ]
  [ "$(echo "$output" | jq -r '.load_bearing_match')" = "true" ]
  [ "$(echo "$output" | jq '.coverage_pct')" = "100" ]
}

@test "json: nested dot-paths are produced (userIdentity.userName, tlsDetails.tlsVersion)" {
  # Generated omits both nested fields the master carries. The flattener
  # must produce object-path dot notation (userIdentity.userName, not e.g.
  # userIdentity[0] or a +content artefact) so the verdict logic can spot
  # the gap. Asserting on `missing_in_generated` proves the exact paths
  # are in the flattened map; a master_field_count threshold alone could
  # be satisfied by the wrong shape (array indices, scalars, etc.) and
  # let regressions through.
  write_json_master "$BATS_TEST_TMPDIR/m.json"
  cat > "$BATS_TEST_TMPDIR/g.json" <<'EOF'
{
  "eventVersion": "1.08",
  "eventSource": "iam.amazonaws.com",
  "eventName": "GetUser",
  "errorCode": "AccessDenied",
  "userIdentity": {"type": "IAMUser"},
  "tlsDetails": {}
}
EOF
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing ""
  [ "$status" -eq 0 ]
  missing="$(echo "$output" | jq -r '.missing_in_generated[]')"
  # Each expected nested path must be present, exactly.
  echo "$missing" | grep -qx 'userIdentity.userName'
  echo "$missing" | grep -qx 'tlsDetails.tlsVersion'
  # And the unrelated peers must NOT be flagged missing — that would
  # indicate the flattener is misshaping `userIdentity.type` etc.
  ! echo "$missing" | grep -qx 'userIdentity.type'
  ! echo "$missing" | grep -qx 'eventName'
}

@test "json: identical inputs flatten to the same set of nested dot-paths (no diffs)" {
  # Companion to the missing-path test: with identical inputs there must
  # be zero value_diffs, zero missing, and the nested paths must be
  # counted on both sides (proves they exist as keys, not just absent).
  write_json_master "$BATS_TEST_TMPDIR/m.json"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing ""
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq '.value_diffs')" = "[]" ]
  [ "$(echo "$output" | jq '.missing_in_generated')" = "[]" ]
  [ "$(echo "$output" | jq '.master_field_count')" -eq 7 ]
  [ "$(echo "$output" | jq '.generated_field_count')" -eq 7 ]
}

# ── JSON: missing load-bearing field → fail ───────────────────────────────────

@test "json: load-bearing field missing from generated → verdict fail" {
  write_json_master "$BATS_TEST_TMPDIR/m.json"
  # Generated lacks errorCode — the SPL would filter on AccessDenied and miss.
  cat > "$BATS_TEST_TMPDIR/g.json" <<'EOF'
{
  "eventVersion": "1.08",
  "eventSource": "iam.amazonaws.com",
  "eventName": "GetUser",
  "userIdentity": {"type": "IAMUser", "userName": "alice"},
  "tlsDetails": {"tlsVersion": "TLSv1.2"}
}
EOF
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing "errorCode"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "fail" ]
  [ "$(echo "$output" | jq -r '.load_bearing_match')" = "false" ]
  [ "$(echo "$output" | jq '.missing_in_generated | index("errorCode")')" != "null" ]
}

# ── JSON: load-bearing value differs → fail ──────────────────────────────────

@test "json: load-bearing field with wrong value → verdict fail" {
  write_json_master "$BATS_TEST_TMPDIR/m.json"
  cat > "$BATS_TEST_TMPDIR/g.json" <<'EOF'
{
  "eventVersion": "1.08",
  "eventSource": "iam.amazonaws.com",
  "eventName": "GetUser",
  "errorCode": "ValidationError",
  "userIdentity": {"type": "IAMUser", "userName": "alice"},
  "tlsDetails": {"tlsVersion": "TLSv1.2"}
}
EOF
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing "errorCode"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "fail" ]
  [ "$(echo "$output" | jq -r '.load_bearing_match')" = "false" ]
  diff_path="$(echo "$output" | jq -r '.value_diffs[] | select(.path=="errorCode") | .load_bearing')"
  [ "$diff_path" = "true" ]
}

# ── NDJSON master + JSON generated (the exact case from the issue report) ────

@test "json: NDJSON master (multi-record) vs single-object generated → first record used" {
  # The samples/master-events cache stores NDJSON-derived single-event files
  # as one JSON object per line. Accept that here.
  cat > "$BATS_TEST_TMPDIR/m.ndjson" <<'EOF'
{"eventVersion":"1.08","eventSource":"iam.amazonaws.com","eventName":"GetUser","errorCode":"AccessDenied","userIdentity":{"type":"IAMUser","userName":"alice"}}
{"eventVersion":"1.08","eventSource":"iam.amazonaws.com","eventName":"ListUsers","errorCode":"AccessDenied","userIdentity":{"type":"IAMUser","userName":"alice"}}
EOF
  cat > "$BATS_TEST_TMPDIR/g.json" <<'EOF'
{"eventVersion":"1.08","eventSource":"iam.amazonaws.com","eventName":"GetUser","errorCode":"AccessDenied","userIdentity":{"type":"IAMUser","userName":"alice"}}
EOF
  run compare --master "$BATS_TEST_TMPDIR/m.ndjson" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing "eventName,errorCode"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "pass" ]
  [ "$(echo "$output" | jq -r '.load_bearing_match')" = "true" ]
}

# ── Records-wrapped CloudTrail JSON (raw upstream shape) ──────────────────────

@test "json: master is {Records:[...]} → first record is compared" {
  cat > "$BATS_TEST_TMPDIR/m.json" <<'EOF'
{"Records":[
  {"eventName":"GetUser","errorCode":"AccessDenied","userIdentity":{"type":"IAMUser"}},
  {"eventName":"ListUsers","errorCode":"AccessDenied","userIdentity":{"type":"IAMUser"}}
]}
EOF
  cat > "$BATS_TEST_TMPDIR/g.json" <<'EOF'
{"eventName":"GetUser","errorCode":"AccessDenied","userIdentity":{"type":"IAMUser"}}
EOF
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing "eventName,errorCode"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "pass" ]
}

# ── Auto-detect across mismatched extensions ─────────────────────────────────

@test "auto: format detected from content, not extension" {
  # File has .log extension but contains JSON. The detector keys off the first
  # non-blank byte (`{`) and not the suffix.
  write_json_master "$BATS_TEST_TMPDIR/m.log"
  write_json_master "$BATS_TEST_TMPDIR/g.log"
  run compare --master "$BATS_TEST_TMPDIR/m.log" \
              --generated "$BATS_TEST_TMPDIR/g.log" \
              --load-bearing "eventName"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "pass" ]
}

# ── Explicit --format flag overrides auto-detection ──────────────────────────

@test "--format json forces the JSON code path" {
  write_json_master "$BATS_TEST_TMPDIR/m.json"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --format json \
              --load-bearing ""
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "pass" ]
}

@test "--format xml forces the XML code path" {
  write_xml_master          "$BATS_TEST_TMPDIR/m.xml"
  write_xml_generated_match "$BATS_TEST_TMPDIR/g.xml"
  run compare --master "$BATS_TEST_TMPDIR/m.xml" \
              --generated "$BATS_TEST_TMPDIR/g.xml" \
              --format xml \
              --load-bearing "EventData.QueryName"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | jq -r '.verdict')" = "pass" ]
}

@test "json: empty array master → hard error (does not flatten to degenerate map)" {
  # Pre-PR-339-review the reducer left `null` after `.[0]` on `[]` and the
  # downstream flattener happily produced an empty/degenerate dot-path map.
  # That silently passed the verdict logic; now it must fail loud.
  printf '[]\n' > "$BATS_TEST_TMPDIR/m.json"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing ""
  [ "$status" -ne 0 ]
  [[ "$output" == *"non-empty event object"* ]] || [[ "$output" == *"cannot parse"* ]]
}

@test "json: {Records:[]} master → hard error (Records[0] is null)" {
  printf '{"Records":[]}\n' > "$BATS_TEST_TMPDIR/m.json"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing ""
  [ "$status" -ne 0 ]
  [[ "$output" == *"non-empty event object"* ]] || [[ "$output" == *"cannot parse"* ]]
}

@test "json: scalar input → hard error" {
  # Single JSON scalar (a number) — not an event object.
  printf '42\n' > "$BATS_TEST_TMPDIR/m.json"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing ""
  [ "$status" -ne 0 ]
  [[ "$output" == *"non-empty event object"* ]] || [[ "$output" == *"cannot parse"* ]]
}

@test "json: empty file → hard error" {
  : > "$BATS_TEST_TMPDIR/m.json"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing ""
  [ "$status" -ne 0 ]
}

@test "auto: mismatched master/generated formats → exit 2 with diagnostic" {
  # XML master + JSON generated almost certainly means the caller pointed
  # at the wrong file. Pre-fix the script silently flattened each via its
  # respective formatter and produced a comparison that looked plausible
  # (zero key overlap → coverage 0%, lots of "missing"). Post-fix it must
  # hard-fail in --format auto so the caller can correct the inputs
  # before reading a misleading verdict.
  write_xml_master  "$BATS_TEST_TMPDIR/m.xml"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.xml" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --load-bearing ""
  [ "$status" -eq 2 ]
  [[ "$output" == *"format"* ]]
  [[ "$output" == *"differ"* ]] || [[ "$output" == *"mismatch"* ]]
}

@test "auto: mismatched JSON master + XML generated → exit 2" {
  # Symmetric to the previous test — direction shouldn't matter.
  write_json_master         "$BATS_TEST_TMPDIR/m.json"
  write_xml_generated_match "$BATS_TEST_TMPDIR/g.xml"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.xml" \
              --load-bearing ""
  [ "$status" -eq 2 ]
}

@test "explicit --format xml on a JSON file: still fails (per-format parser, not auto)" {
  # When --format is set explicitly the auto-detect mismatch check is
  # skipped — the user asked for that format. The XML parser will then
  # fail on a JSON file with a parse error, which is the right outcome:
  # the user's explicit request is honoured but garbage input still
  # surfaces as a non-zero exit.
  write_json_master "$BATS_TEST_TMPDIR/m.json"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --format xml \
              --load-bearing ""
  [ "$status" -ne 0 ]
}

@test "--format with unsupported value → exit 2" {
  write_json_master "$BATS_TEST_TMPDIR/m.json"
  write_json_master "$BATS_TEST_TMPDIR/g.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.json" \
              --format yaml \
              --load-bearing ""
  [ "$status" -eq 2 ]
  [[ "$output" == *"unsupported format"* ]]
}

# ── B1: Structural diff — empty objects/arrays as terminal paths ──────────────

@test "json: missing empty {} placeholder is reported in missing_in_generated" {
  master='{"userIdentity":{"sessionContext":{"webIdFederationData":{},"attributes":{"mfa":"false"}}}}'
  generated='{"userIdentity":{"sessionContext":{"attributes":{"mfa":"false"}}}}'
  echo "$master" > "$BATS_TEST_TMPDIR/master.json"
  echo "$generated" > "$BATS_TEST_TMPDIR/gen.json"

  run "$SCRIPTS_DIR/compare-fidelity.sh" \
    --master "$BATS_TEST_TMPDIR/master.json" --generated "$BATS_TEST_TMPDIR/gen.json"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.missing_in_generated | index("userIdentity.sessionContext.webIdFederationData") != null'
}

@test "json: missing empty [] placeholder is reported in missing_in_generated" {
  master='{"requestParameters":{"emptyList":[],"keep":"x"}}'
  generated='{"requestParameters":{"keep":"x"}}'
  echo "$master" > "$BATS_TEST_TMPDIR/master.json"
  echo "$generated" > "$BATS_TEST_TMPDIR/gen.json"

  run "$SCRIPTS_DIR/compare-fidelity.sh" \
    --master "$BATS_TEST_TMPDIR/master.json" --generated "$BATS_TEST_TMPDIR/gen.json"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.missing_in_generated | index("requestParameters.emptyList") != null'
}

@test "json: matching empty {} on both sides does not appear in any diff" {
  master='{"userIdentity":{"sessionContext":{"webIdFederationData":{}}}}'
  generated='{"userIdentity":{"sessionContext":{"webIdFederationData":{}}}}'
  echo "$master" > "$BATS_TEST_TMPDIR/master.json"
  echo "$generated" > "$BATS_TEST_TMPDIR/gen.json"

  run "$SCRIPTS_DIR/compare-fidelity.sh" \
    --master "$BATS_TEST_TMPDIR/master.json" --generated "$BATS_TEST_TMPDIR/gen.json"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '(.missing_in_generated | length) == 0'
  echo "$output" | jq -e '(.extra_in_generated   | length) == 0'
}

@test "xml: missing empty element <X/> is reported in missing_in_generated" {
  echo '<Event><Empty/><Keep>x</Keep></Event>' > "$BATS_TEST_TMPDIR/master.xml"
  echo '<Event><Keep>x</Keep></Event>'         > "$BATS_TEST_TMPDIR/gen.xml"

  run "$SCRIPTS_DIR/compare-fidelity.sh" \
    --master "$BATS_TEST_TMPDIR/master.xml" --generated "$BATS_TEST_TMPDIR/gen.xml"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '[.missing_in_generated[] | select(endswith("Empty"))] | length > 0'
}

# ── B2: Pattern path matching ([*] / {*}) ─────────────────────────────────────

@test "load-bearing: pattern path [*] matches concrete [N] in master/generated" {
  master='{"requestParameters":{"organizationArn":["arn:aws:organizations::1:o-aaa"]}}'
  generated='{"requestParameters":{"organizationArn":["arn:aws:organizations::1:o-aaa"]}}'
  echo "$master" > "$BATS_TEST_TMPDIR/master.json"
  echo "$generated" > "$BATS_TEST_TMPDIR/gen.json"

  run "$SCRIPTS_DIR/compare-fidelity.sh" \
    --master "$BATS_TEST_TMPDIR/master.json" \
    --generated "$BATS_TEST_TMPDIR/gen.json" \
    --load-bearing "requestParameters.organizationArn[*]"

  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_match == true'
  echo "$output" | jq -e '.verdict == "pass"'
}

@test "load-bearing: pattern path [*] does NOT match when field absent in generated" {
  master='{"requestParameters":{"organizationArn":["arn:aws:organizations::1:o-aaa"]}}'
  generated='{"requestParameters":{"otherField":"x"}}'
  echo "$master" > "$BATS_TEST_TMPDIR/master.json"
  echo "$generated" > "$BATS_TEST_TMPDIR/gen.json"

  run "$SCRIPTS_DIR/compare-fidelity.sh" \
    --master "$BATS_TEST_TMPDIR/master.json" \
    --generated "$BATS_TEST_TMPDIR/gen.json" \
    --load-bearing "requestParameters.organizationArn[*]"

  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_match == false'
  echo "$output" | jq -e '.verdict == "fail"'
}

# ── B3: Load-bearing existence precheck ──────────────────────────────────────

@test "load-bearing: pattern absent from master → load_bearing_master_missing + verdict fail" {
  master='{"requestParameters":{"someField":"x"}}'
  generated='{"requestParameters":{"someField":"x","organizationArn":["a"]}}'
  echo "$master" > "$BATS_TEST_TMPDIR/master.json"
  echo "$generated" > "$BATS_TEST_TMPDIR/gen.json"

  run "$SCRIPTS_DIR/compare-fidelity.sh" \
    --master "$BATS_TEST_TMPDIR/master.json" \
    --generated "$BATS_TEST_TMPDIR/gen.json" \
    --load-bearing "requestParameters.organizationArn[*]"

  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_master_missing | index("requestParameters.organizationArn[*]") != null'
  echo "$output" | jq -e '.verdict == "fail"'
}

# ── Regression: regex metacharacters in literal load-bearing paths ───────────

@test "load-bearing: literal XML attribute path with + treats + as literal" {
  echo '<Event><System><Provider Name="Microsoft-Windows-Sysmon"/></System></Event>' \
    > "$BATS_TEST_TMPDIR/master.xml"
  cp "$BATS_TEST_TMPDIR/master.xml" "$BATS_TEST_TMPDIR/gen.xml"

  run "$SCRIPTS_DIR/compare-fidelity.sh" \
    --master "$BATS_TEST_TMPDIR/master.xml" \
    --generated "$BATS_TEST_TMPDIR/gen.xml" \
    --load-bearing 'System.Provider.+@Name'

  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_master_missing == []'
  echo "$output" | jq -e '.load_bearing_match == true'
  echo "$output" | jq -e '.verdict == "pass"'
}

# ── Aggregate load-bearing modes: glob membership + distinct-count cardinality ─
#
# Volumetric / threshold detections (e.g. aws_excessive_security_scanning:
# `eventName=Describe* OR List* OR Get* | stats dc(signature) BY user | where
# dc_events > 50`) do not filter on a single literal value. The load-bearing
# semantic is aggregate over the whole generated burst: every eventName matches
# a glob, the distinct count crosses a threshold, and the group-by key is single
# valued. These modes evaluate against ALL generated records, not just the first.

# Write an NDJSON burst of $1 events; eventName cycles Describe<N>, all share
# one userName ("scanner").
write_describe_burst() {
  local file="$1" count="$2" i
  : > "$file"
  for ((i = 0; i < count; i++)); do
    printf '{"eventSource":"ec2.amazonaws.com","eventName":"Describe%03d","userIdentity":{"type":"AssumedRole","userName":"scanner"}}\n' "$i" >> "$file"
  done
}

@test "load-bearing glob: every generated eventName matches Describe*|List*|Get* → pass" {
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 5
  # Master is one representative event with a different concrete eventName.
  echo '{"eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","userIdentity":{"type":"AssumedRole","userName":"cloudsploit"}}' \
    > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "eventName~Describe*|List*|Get*"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_aggregate[0].kind == "glob"'
  echo "$output" | jq -e '.load_bearing_aggregate[0].violations == 0'
  echo "$output" | jq -e '.load_bearing_aggregate[0].checked == 5'
  echo "$output" | jq -e '.load_bearing_match == true'
  echo "$output" | jq -e '.verdict == "pass"'
}

@test "load-bearing glob: one generated event outside the glob → violation, fail" {
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 4
  echo '{"eventSource":"s3.amazonaws.com","eventName":"PutObject","userIdentity":{"type":"AssumedRole","userName":"scanner"}}' \
    >> "$BATS_TEST_TMPDIR/g.ndjson"
  echo '{"eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "eventName~Describe*|List*|Get*"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_aggregate[0].violations == 1'
  echo "$output" | jq -e '.load_bearing_aggregate[0].match == false'
  echo "$output" | jq -e '.verdict == "fail"'
}

@test "load-bearing cardinality: dc(eventName)>50 satisfied by a 53-event burst → pass" {
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 53
  echo '{"eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "dc(eventName)>50"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_aggregate[0].kind == "cardinality"'
  echo "$output" | jq -e '.load_bearing_aggregate[0].distinct == 53'
  echo "$output" | jq -e '.load_bearing_aggregate[0].match == true'
  echo "$output" | jq -e '.verdict == "pass"'
}

@test "load-bearing cardinality: dc(eventName)>50 unmet by a small burst → fail" {
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 5
  echo '{"eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "dc(eventName)>50"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_aggregate[0].distinct == 5'
  echo "$output" | jq -e '.load_bearing_aggregate[0].match == false'
  echo "$output" | jq -e '.verdict == "fail"'
}

@test "load-bearing cardinality: dc(userName)==1 enforces single group key" {
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 3
  echo '{"eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "dc(userIdentity.userName)==1"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_aggregate[0].distinct == 1'
  echo "$output" | jq -e '.load_bearing_aggregate[0].match == true'
  echo "$output" | jq -e '.verdict == "pass"'

  # Add a second distinct user → group key is no longer single → fail.
  echo '{"eventName":"DescribeFleets","userIdentity":{"type":"AssumedRole","userName":"other"}}' \
    >> "$BATS_TEST_TMPDIR/g.ndjson"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "dc(userIdentity.userName)==1"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_aggregate[0].distinct == 2'
  echo "$output" | jq -e '.verdict == "fail"'
}

@test "load-bearing: full volumetric detection — glob + dc + single-key all pass despite literal value diffs" {
  # master is
  # one DescribeInstances/cloudsploit event; generated is a 53-event Describe*
  # burst by a single "scanner" user. Literal eventName/userName differ from the
  # master, but every aggregate semantic the SPL relies on is satisfied.
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 53
  echo '{"eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","userIdentity":{"type":"AssumedRole","userName":"cloudsploit"}}' \
    > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "eventName~Describe*|List*|Get*,dc(eventName)>50,dc(userIdentity.userName)==1"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '[.load_bearing_aggregate[] | select(.match)] | length == 3'
  echo "$output" | jq -e '.load_bearing_match == true'
  echo "$output" | jq -e '.verdict == "pass"'
}

@test "load-bearing: corrupt NDJSON after valid first record → hard error, not silent []" {
  # flatten_json_all must not silently fall back to [] when later records are
  # invalid JSON — that would make generated_event_count appear as 0 and mask
  # file corruption with a misleading (usually fail) verdict. Hard error instead.
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 3
  printf 'this is not json\n' >> "$BATS_TEST_TMPDIR/g.ndjson"
  echo '{"eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "dc(eventName)>2"
  [ "$status" -ne 0 ]
  ! echo "$output" | grep -q '"verdict"'
}

@test "load-bearing cardinality: empty generated burst never yields a pass" {
  # A degenerate generated file (engine emitted nothing) must never satisfy a
  # cardinality token whose threshold a zero distinct-count would otherwise
  # pass (e.g. dc(x)<=0 or dc(x)==0) — a detection cannot fire with no events.
  # An empty file hard-errors at the flatten step, which is itself a non-pass;
  # the cardinality match also guards on (generated_event_count > 0) as defense
  # for any path that yields an empty burst without erroring.
  : > "$BATS_TEST_TMPDIR/g.ndjson"
  echo '{"eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "dc(eventName)<=0"
  [ "$status" -ne 0 ]
  # Crucially, no passing verdict is ever emitted for an empty burst.
  ! echo "$output" | grep -q '"verdict": *"pass"'
}

@test "load-bearing cardinality: single = is accepted as an alias for ==" {
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 3
  echo '{"eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "dc(userIdentity.userName)=1"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_aggregate[0].op == "=="'
  echo "$output" | jq -e '.load_bearing_aggregate[0].match == true'
  echo "$output" | jq -e '.verdict == "pass"'
}

@test "load-bearing: mixed exact + aggregate tokens both enforced" {
  write_describe_burst "$BATS_TEST_TMPDIR/g.ndjson" 53
  # Generated all carry eventSource=ec2 (matches master) — exact token passes;
  # aggregate tokens pass too.
  echo '{"eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' \
    > "$BATS_TEST_TMPDIR/m.json"
  run compare --master "$BATS_TEST_TMPDIR/m.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "eventSource,dc(eventName)>50"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.load_bearing_match == true'
  echo "$output" | jq -e '.verdict == "pass"'

  # Break the exact token: master eventSource the generated burst never carries.
  echo '{"eventSource":"iam.amazonaws.com","eventName":"DescribeInstances","userIdentity":{"userName":"x"}}' \
    > "$BATS_TEST_TMPDIR/m2.json"
  run compare --master "$BATS_TEST_TMPDIR/m2.json" \
              --generated "$BATS_TEST_TMPDIR/g.ndjson" \
              --load-bearing "eventSource,dc(eventName)>50"
  [ "$status" -eq 0 ]
  echo "$output" | jq -e '.verdict == "fail"'
}
