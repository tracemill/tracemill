#!/usr/bin/env bats

# Tests for the shared bats helpers in helpers.bash. These exist so that
# silent regressions in the helpers (e.g. the previous start_server
# port-detection bug) surface as a focused test failure rather than as
# misleading downstream noise.

bats_require_minimum_version 1.5.0
load helpers

setup() { scenario_authoring_setup; }
teardown() { stop_local_server; }

@test "start_local_server: launches and exports SERVER_PID + SERVER_PORT" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  printf 'hello\n' > "$doc/x.txt"

  start_local_server "$doc"
  [ -n "${SERVER_PID:-}" ]
  [ -n "${SERVER_PORT:-}" ]
  # Port must be a non-empty number > 0
  [[ "$SERVER_PORT" =~ ^[0-9]+$ ]]
  [ "$SERVER_PORT" -gt 0 ]
  # Server actually responds
  body="$(curl -fsS "http://127.0.0.1:$SERVER_PORT/x.txt")"
  [ "$body" = "hello" ]
}

# NOTE: a "hard-fails on banner timeout" test is intentionally omitted —
# python3's `http.server` actually starts and serves 404s on a missing
# document root, and there's no clean way to provoke the
# port-banner-never-arrives path without mocking python3 itself. The
# `return 1` failure mode is exercised in production only when something
# global is broken (no python3, port 0 unavailable, etc.); the implementation
# is reviewed by inspection.

@test "stop_local_server: idempotent — safe to call when no server is running" {
  # No prior start_local_server. Must not error, must not export anything.
  run stop_local_server
  [ "$status" -eq 0 ]
  [ -z "${SERVER_PID:-}" ]
  [ -z "${SERVER_PORT:-}" ]
}

@test "stop_local_server: kills the running server and clears env" {
  doc="$BATS_TEST_TMPDIR/doc"
  mkdir -p "$doc"
  start_local_server "$doc"
  pid="$SERVER_PID"
  stop_local_server
  # SERVER_PID/SERVER_PORT cleared
  [ -z "${SERVER_PID:-}" ]
  [ -z "${SERVER_PORT:-}" ]
  # Process gone (kill -0 returns non-zero on dead pid)
  ! kill -0 "$pid" 2>/dev/null
}

@test "scenario_authoring_setup: REPO_ROOT, SCRIPTS_DIR, FIXTURES are populated and exist" {
  [ -n "$REPO_ROOT" ]
  [ -d "$REPO_ROOT" ]
  [ -d "$SCRIPTS_DIR" ]
  [ -d "$FIXTURES" ]
  [ -x "$SCRIPTS_DIR/extract-events.sh" ]
  [ -d "$SCENARIO_AUTHORING_CACHE" ]
}
