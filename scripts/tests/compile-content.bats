#!/usr/bin/env bats

# A stub `tracemill` stands in for the CLI: it reports $STUB_VERSION and, for
# `validate --dir <dir>`, prints $STUB_<dir>_ERR to stderr and exits
# $STUB_<dir>_RC. That pins the script's own logic (version guard, exit status,
# CI annotations) without a real CLI.

setup() {
  export GITHUB_ACTIONS=true
  repo_root="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  script="$repo_root/scripts/compile-content.sh"
  lib="$BATS_TEST_TMPDIR/library"
  mkdir -p "$lib/scenarios" "$lib/jobs" "$BATS_TEST_TMPDIR/bin"
  printf '{"min_cli_version":"0.11.3"}\n' > "$lib/library.json"
  cat > "$BATS_TEST_TMPDIR/bin/tracemill" <<'STUB'
#!/usr/bin/env bash
if [[ "$1" == version ]]; then echo "Version:    $STUB_VERSION"; exit 0; fi
var_err="STUB_${3}_ERR"; var_rc="STUB_${3}_RC"
printf '%s' "${!var_err:-}" >&2
echo "1 files checked"
exit "${!var_rc:-0}"
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/tracemill"
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
  export STUB_VERSION=0.11.3
}

run_script() {
  run bash -c 'cd "$1" && "$2"' _ "$lib" "$script"
}

@test "passes when both directories validate" {
  run_script
  [ "$status" -eq 0 ]
  [[ "$output" != *"::error"* ]]
}

@test "refuses a CLI older than min_cli_version" {
  STUB_VERSION=0.11.2 run_script
  [ "$status" -eq 2 ]
  [[ "$output" == *"older than min_cli_version 0.11.3"* ]]
}

@test "accepts a dev build" {
  STUB_VERSION=dev run_script
  [ "$status" -eq 0 ]
}

@test "accepts a CLI newer than min_cli_version" {
  STUB_VERSION=0.12.0 run_script
  [ "$status" -eq 0 ]
}

@test "a per-file failure fails the run with a file annotation" {
  export STUB_jobs_ERR=$'aws/foo ... FAIL (event aws.cloudtrail@v1: schema validation failed)\n'
  export STUB_jobs_RC=1
  run_script
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error file=jobs/aws/foo.yaml::event aws.cloudtrail@v1: schema validation failed)"* ]]
}

@test "unparsable YAML is annotated on the file that broke discovery" {
  export STUB_scenarios_ERR=$'Error: walkdir "scenarios": read content file "scenarios/x/bad.yaml": yaml: line 3: did not find expected key\n'
  export STUB_scenarios_RC=1
  run_script
  [ "$status" -eq 1 ]
  [[ "$output" == *"::error file=scenarios/x/bad.yaml::yaml: line 3: did not find expected key"* ]]
}
