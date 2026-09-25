#!/usr/bin/env bats

setup() {
  repo_root="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  tally="$repo_root/scripts/coverage-tally.sh"
  badges="$repo_root/scripts/coverage-badges.sh"
  test_library="$BATS_TEST_TMPDIR/library"
  mkdir -p "$test_library"
  printf '{"min_cli_version":"test"}\n' > "$test_library/library.json"
  cp -R "$BATS_TEST_DIRNAME/fixtures/coverage-tally/basic/." "$test_library/"
}

tally_json() {
  (cd "$test_library" && "$tally")
}

@test "defaults to splunk only and counts detections, not tests" {
  run tally_json
  [ "$status" -eq 0 ]
  [ "$(jq -c '.siems' <<< "$output")" = '["splunk"]' ]
  [ "$(jq -c '.totals' <<< "$output")" = '{"detections":2,"tests":3,"tests_without_detection":1,"attack_scenarios":3,"benign_controls":1,"detections_with_benign_control":1,"techniques":2}' ]
  [ "$(jq -c '.by_source' <<< "$output")" = '{"splunk":{"o365":1,"windows":1}}' ]
  [ "$(jq -r '.schema_version' <<< "$output")" = "1" ]
}

@test "jobs sharing a detection id merge into one detection under the ESCU title" {
  run tally_json
  [ "$status" -eq 0 ]
  [ "$(jq -c '.detections[] | select(.id == "00000000-0000-4000-8000-000000000001") | [.title, .tests, .techniques, .attack_scenarios, .benign_controls]' <<< "$output")" = '["Access LSASS Memory for Dump Creation",["LSASS dump via comsvcs","LSASS dump via procdump"],["T1003","T1003.001"],3,1]' ]
}

@test "a detection with no workloads or mitre counts as zero with no techniques" {
  run tally_json
  [ "$status" -eq 0 ]
  [ "$(jq -c '.detections[] | select(.title == "Bare Detection") | [.attack_scenarios, .benign_controls, .techniques]' <<< "$output")" = '[0,0,[]]' ]
}

@test "detections are sorted by siem then title and keep non-ESCU titles verbatim" {
  export COVERAGE_SIEMS=splunk,crowdstrike
  run tally_json
  [ "$status" -eq 0 ]
  [ "$(jq -c '[.detections[] | [.siem, .source, .title]]' <<< "$output")" = '[["crowdstrike","aws","AWS - CloudTrail - S3 Bucket Exposed via ACL"],["splunk","windows","Access LSASS Memory for Dump Creation"],["splunk","o365","Bare Detection"]]' ]
}

@test "crowdstrike is included only when named and techniques dedupe across siems" {
  export COVERAGE_SIEMS=splunk,crowdstrike
  run tally_json
  [ "$status" -eq 0 ]
  [ "$(jq -r '.totals.detections' <<< "$output")" = "3" ]
  [ "$(jq -r '.totals.techniques' <<< "$output")" = "3" ]
  [ "$(jq -c '.by_source.crowdstrike' <<< "$output")" = '{"aws":1}' ]
}

@test "rejects a misspelled siem" {
  export COVERAGE_SIEMS=splnk
  run tally_json
  [ "$status" -eq 2 ]
  [[ "$output" == *"COVERAGE_SIEMS entry 'splnk'"* ]]
}

@test "rejects a path-like siem" {
  export COVERAGE_SIEMS=../jobs
  run tally_json
  [ "$status" -eq 2 ]
}

@test "fails with no job files" {
  rm -rf "$test_library/jobs/splunk"/*
  run tally_json
  [ "$status" -eq 1 ]
  [[ "$output" == *"no job files"* ]]
}

@test "refuses to run outside the library root" {
  run bash -c 'cd "$1" && "$2"' _ "$BATS_TEST_TMPDIR" "$tally"
  [ "$status" -eq 2 ]
}

@test "writes three shields endpoint badges" {
  (cd "$test_library" && COVERAGE_SIEMS=splunk,crowdstrike "$tally") > "$BATS_TEST_TMPDIR/coverage.json"
  run "$badges" "$BATS_TEST_TMPDIR/coverage.json" "$BATS_TEST_TMPDIR/badges"
  [ "$status" -eq 0 ]
  [ "$(jq -c . "$BATS_TEST_TMPDIR/badges/splunk-detections.json")" = '{"schemaVersion":1,"label":"Splunk ESCU detections","message":"2","color":"0d9488"}' ]
  [ "$(jq -c . "$BATS_TEST_TMPDIR/badges/attack-scenarios.json")" = '{"schemaVersion":1,"label":"attack scenarios","message":"4","color":"0d9488"}' ]
  [ "$(jq -c . "$BATS_TEST_TMPDIR/badges/attack-techniques.json")" = '{"schemaVersion":1,"label":"ATT&CK techniques","message":"3","color":"0d9488"}' ]
}

@test "badges reject an unsupported schema_version" {
  printf '{"schema_version":2}\n' > "$BATS_TEST_TMPDIR/coverage.json"
  run "$badges" "$BATS_TEST_TMPDIR/coverage.json" "$BATS_TEST_TMPDIR/badges"
  [ "$status" -eq 2 ]
  [[ "$output" == *"schema_version"* ]]
}
