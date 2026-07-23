#!/usr/bin/env bats

setup() {
  # The linter formats diagnostics differently under CI (GitHub `::error`
  # annotations) than locally (`FAIL: <file> (<msg>)`). Pin CI mode so the
  # suite is deterministic regardless of the ambient environment and covers
  # the annotation path that actually runs in CI; the one local-format test
  # clears this signal itself.
  export GITHUB_ACTIONS=true
  repo_root="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  linter="$repo_root/scripts/check-job-taxonomy.sh"
  fixture_root="$BATS_TEST_DIRNAME/fixtures/job-taxonomy"
  test_library="$BATS_TEST_TMPDIR/library"
  mkdir -p "$test_library"
  printf '{"min_cli_version":"test"}\n' > "$test_library/library.json"
}

run_fixture() {
  cp -R "$fixture_root/$1/." "$test_library/"
  run bash -c 'cd "$1" && "$2"' _ "$test_library" "$linter"
}

@test "accepts unique names, optional Detection, and alert or none expectations without Detection" {
  run_fixture valid

  [ "$status" -eq 0 ]
  [[ "$output" == *"3 job(s) named, normalized-unique"* ]]
}

@test "rejects missing and whitespace-only Test names" {
  run_fixture blank-names

  [ "$status" -eq 1 ]
  [[ "$output" == *"::error file=jobs/splunk/example/missing-name.yaml::missing or blank Test name"* ]]
  [[ "$output" == *"::error file=jobs/splunk/example/blank-name.yaml::missing or blank Test name"* ]]
}

@test "emits human-readable diagnostics outside CI" {
  unset GITHUB_ACTIONS
  run_fixture blank-names

  [ "$status" -eq 1 ]
  [[ "$output" == *"FAIL: jobs/splunk/example/missing-name.yaml (missing or blank Test name)"* ]]
}

@test "normalizes case and whitespace and reports both colliding content IDs" {
  run_fixture duplicate-names

  [ "$status" -eq 1 ]
  [[ "$output" == *"jobs/splunk/example/first"* ]]
  [[ "$output" == *"jobs/splunk/example/second"* ]]
  [[ "$output" == *'normalized Test name "detect suspicious activity"'* ]]
}

@test "rejects workload-level Detection declarations" {
  run_fixture workload-detection

  [ "$status" -eq 1 ]
  [[ "$output" == *"workload-level expectation.detection is not allowed (1 declaration(s))"* ]]
}

@test "rejects multiple top-level Detections" {
  run_fixture multiple-detections

  [ "$status" -eq 1 ]
  [[ "$output" == *"top-level detection must be a single mapping when present"* ]]
}

@test "requires the exact native ESCU title form" {
  run_fixture invalid-escu-title

  [ "$status" -eq 1 ]
  [[ "$output" == *'ESCU detection.name must use exact native title form "ESCU - <name> - Rule"'* ]]
}
