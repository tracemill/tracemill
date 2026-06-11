#!/usr/bin/env bats

# Dispatcher-level error paths for $SCRIPTS_DIR/extract-events.sh
# (.claude/skills/scenario-authoring/scripts/extract-events.sh) — usage errors,
# missing flags, missing dataset, unknown mode / flag, and dep-preflight
# behaviour. Per-mode correctness lives in the other suites.

bats_require_minimum_version 1.5.0
load helpers

setup() { scenario_authoring_setup; }

@test "dispatcher: --dataset required" {
  run extract_events --mode summary --key k
  [ "$status" -eq 2 ]
  [[ "$output" == *"--dataset required"* ]]
}

@test "dispatcher: --mode required" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" --key k
  [ "$status" -eq 2 ]
  [[ "$output" == *"--mode required"* ]]
}

@test "dispatcher: dataset not found surfaces dataset path" {
  run extract_events --dataset /tmp/does-not-exist-for-real \
    --mode summary --key k
  [ "$status" -eq 2 ]
  [[ "$output" == *"dataset not found: /tmp/does-not-exist-for-real"* ]]
}

@test "dispatcher: unknown flag rejected with exit 2" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --mode summary --key k --bogus oops
  [ "$status" -eq 2 ]
  [[ "$output" == *"unknown flag: --bogus"* ]]
}

@test "dispatcher: unknown mode rejected with exit 2" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --mode morph --key k
  [ "$status" -eq 2 ]
  [[ "$output" == *"unknown mode: morph"* ]]
}

@test "dispatcher: missing --key surfaces before any handler runs" {
  # Even extract mode, which has additional required flags, fails on --key
  # first (the dispatcher checks --key before --out / --value).
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" --mode extract
  [ "$status" -eq 2 ]
  [[ "$output" == *"--key required"* ]]
}

# ── Flag-parsing: missing value for a --flag (set -u hazard) ─────────────────
# Without the `require_flag_value` guard, `--dataset` at the end of args or
# followed immediately by another --flag would trip `set -u` with an
# "unbound variable" error (exit 1) instead of our intended usage error.

@test "flag parser: --dataset at end of args → exit 2 with 'requires a value'" {
  run extract_events --dataset
  [ "$status" -eq 2 ]
  [[ "$output" == *"--dataset requires a value"* ]]
}

@test "flag parser: --dataset followed by another --flag → exit 2" {
  run extract_events --dataset --mode summary
  [ "$status" -eq 2 ]
  [[ "$output" == *"--dataset requires a value"* ]]
}

@test "flag parser: --key at end of args → exit 2" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" --mode summary --key
  [ "$status" -eq 2 ]
  [[ "$output" == *"--key requires a value"* ]]
}

@test "flag parser: --mode at end of args → exit 2" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" --mode
  [ "$status" -eq 2 ]
  [[ "$output" == *"--mode requires a value"* ]]
}

@test "flag parser: --value followed by another --flag → exit 2" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --mode extract --key k --value --out /tmp/x
  [ "$status" -eq 2 ]
  [[ "$output" == *"--value requires a value"* ]]
}

@test "flag parser: --out at end of args → exit 2" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" \
    --mode samples --key k --out
  [ "$status" -eq 2 ]
  [[ "$output" == *"--out requires a value"* ]]
}

@test "flag parser: --format at end of args → exit 2" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" --format
  [ "$status" -eq 2 ]
  [[ "$output" == *"--format requires a value"* ]]
}

# Empty-string flag values are treated the same as a missing value — the
# `require_flag_value` guard rejects both because an empty $KEY is
# semantically meaningless. Either error message is acceptable (both
# exit 2, both blame the --key flag).
@test "flag parser: --key '' is rejected with a \"requires a value\"-ish error" {
  run extract_events --dataset "$FIXTURES/dataset-sysmon.xml" --mode summary --key ""
  [ "$status" -eq 2 ]
  [[ "$output" == *"--key"* ]]
}

@test "dispatcher: preflight fails when a required command is missing" {
  # Simulate a sparse PATH that has head/grep/awk/sed (provided by coreutils
  # / busybox on every PATH entry below) but deliberately lacks jq. The
  # exact missing cmd depends on what's available in /bin and /usr/bin on
  # the test host, so we just assert exit 127 + the preflight diagnostic
  # format. Fragments under /bin: /usr/bin are present on every CI runner.
  # `run -127` declares the expected exit code so bats doesn't warn about
  # "Command not found" (exit 127 is exactly what we're asserting here).
  # On a system where jq/yq live under /usr/bin, the script succeeds and
  # we skip; otherwise we verify the preflight message shape.
  PATH=/usr/bin:/bin run -127 extract_events \
    --dataset "$FIXTURES/dataset-sysmon.xml" --mode summary --key k || true
  if [ "$status" -eq 127 ]; then
    [[ "$output" == *"required command"* ]]
    [[ "$output" == *"not found in PATH"* ]]
  else
    skip "jq/yq live under /usr/bin on this host — preflight path unexercised"
  fi
}
