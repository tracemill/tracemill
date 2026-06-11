#!/usr/bin/env bash
# Shared setup for scenario-authoring bats tests.
#
# Usage in a .bats file:
#   load helpers
#   setup() { scenario_authoring_setup; }
#
# Exports:
#   REPO_ROOT              — repository root (computed from BATS_TEST_DIRNAME)
#   SCRIPTS_DIR            — .claude/skills/scenario-authoring/scripts/ (the scripts under test)
#   FIXTURES               — .claude/skills/scenario-authoring/scripts/fixtures/
#   SCENARIO_AUTHORING_CACHE — per-test temp cache (honored by fetch-dataset.sh)

scenario_authoring_setup() {
  # tests live at <repo>/.claude/skills/scenario-authoring/scripts/tests/, so
  # SCRIPTS_DIR is one level up. Repo root is four levels up — but it's
  # only exported for callers that genuinely need it; SCRIPTS_DIR is the
  # primary handle.
  export SCRIPTS_DIR="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  export FIXTURES="$SCRIPTS_DIR/fixtures"
  export REPO_ROOT="$(cd "$SCRIPTS_DIR/../../../.." && pwd)"

  # Per-test cache so tests don't leak state into each other or the repo.
  export SCENARIO_AUTHORING_CACHE="$BATS_TEST_TMPDIR/cache"
  mkdir -p "$SCENARIO_AUTHORING_CACHE"
}

# extract_events wraps the dispatcher call so tests are concise.
# Usage: run extract_events --dataset ... --mode summary --key ...
extract_events() {
  "$SCRIPTS_DIR/extract-events.sh" "$@"
}

# start_local_server starts a Python http.server in $1 (document root) on
# a 127.0.0.1 ephemeral port and exports SERVER_PID + SERVER_PORT for the
# caller. Hard-fails (exits the test) if the server doesn't report a port
# within ~5 seconds — silent fall-throughs to an unset SERVER_PORT
# previously caused misleading test failures downstream.
#
# Caller should invoke `stop_local_server` (defined below) from its
# teardown(). That helper is safe to call unconditionally — it no-ops
# when no server is running — so each suite can include
# `teardown() { stop_local_server; }` without bookkeeping boilerplate.
start_local_server() {
  local doc_root="$1"
  # PYTHONUNBUFFERED forces http.server to flush the "Serving HTTP on …
  # port N" banner immediately so we can parse the ephemeral port.
  PYTHONUNBUFFERED=1 python3 -m http.server --directory "$doc_root" \
      --bind 127.0.0.1 0 >"$BATS_TEST_TMPDIR/srv.log" 2>&1 &
  SERVER_PID=$!
  export SERVER_PID

  for _ in {1..50}; do
    if grep -qE 'port [0-9]+' "$BATS_TEST_TMPDIR/srv.log" 2>/dev/null; then
      SERVER_PORT="$(grep -oE 'port [0-9]+' "$BATS_TEST_TMPDIR/srv.log" \
                       | awk '{print $2}' | head -1)"
      export SERVER_PORT
      [[ -n "$SERVER_PORT" ]] || {
        kill "$SERVER_PID" 2>/dev/null || true
        echo "start_local_server: empty port parsed from banner: $(cat "$BATS_TEST_TMPDIR/srv.log")" >&2
        return 1
      }
      return 0
    fi
    sleep 0.1
  done

  kill "$SERVER_PID" 2>/dev/null || true
  echo "start_local_server: server never reported a port (log: $(cat "$BATS_TEST_TMPDIR/srv.log" 2>/dev/null))" >&2
  return 1
}

# stop_local_server kills the background server if it's still running.
# Idempotent — safe to call from teardown unconditionally.
stop_local_server() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    unset SERVER_PID SERVER_PORT
  fi
}

# start_mock_splunk launches the stateful HTTP mock at $BATS_TEST_DIRNAME/
# mock_splunk.py (see that file for the config + log schemas) and exports
# MOCK_SPLUNK_PID, MOCK_SPLUNK_PORT, MOCK_SPLUNK_URL, MOCK_SPLUNK_LOG.
#
# Usage:
#   config="$BATS_TEST_TMPDIR/mock-config.json"
#   log="$BATS_TEST_TMPDIR/mock-log.jsonl"
#   echo '{"responses": {"/services/saved/searches": [201]}}' > "$config"
#   start_mock_splunk "$config" "$log"
#   # ... call extract-spl-groupby.sh against $MOCK_SPLUNK_URL ...
#   stop_mock_splunk  # idempotent; safe in teardown
#
# Hard-fails if the mock doesn't report a port within ~5 seconds. Caller
# should add `teardown() { stop_mock_splunk; }` (or share a teardown that
# calls both stop_local_server and stop_mock_splunk) so a kill leak from
# one test doesn't poison the next.
start_mock_splunk() {
  local config_file="$1" log_file="$2"
  : > "$log_file"  # fresh log per call so prior runs don't leak in
  PYTHONUNBUFFERED=1 \
    MOCK_SPLUNK_CONFIG="$config_file" \
    MOCK_SPLUNK_LOG="$log_file" \
    python3 "$BATS_TEST_DIRNAME/mock_splunk.py" \
      >"$BATS_TEST_TMPDIR/mock-splunk.log" 2>&1 &
  MOCK_SPLUNK_PID=$!
  export MOCK_SPLUNK_PID MOCK_SPLUNK_LOG="$log_file"

  for _ in {1..50}; do
    if grep -qE 'port [0-9]+' "$BATS_TEST_TMPDIR/mock-splunk.log" 2>/dev/null; then
      MOCK_SPLUNK_PORT="$(grep -oE 'port [0-9]+' "$BATS_TEST_TMPDIR/mock-splunk.log" \
                           | awk '{print $2}' | head -1)"
      [[ -n "$MOCK_SPLUNK_PORT" ]] || {
        kill "$MOCK_SPLUNK_PID" 2>/dev/null || true
        echo "start_mock_splunk: empty port parsed from banner: $(cat "$BATS_TEST_TMPDIR/mock-splunk.log")" >&2
        return 1
      }
      MOCK_SPLUNK_URL="http://127.0.0.1:$MOCK_SPLUNK_PORT"
      export MOCK_SPLUNK_PORT MOCK_SPLUNK_URL
      return 0
    fi
    sleep 0.1
  done

  kill "$MOCK_SPLUNK_PID" 2>/dev/null || true
  echo "start_mock_splunk: mock never reported a port (log: $(cat "$BATS_TEST_TMPDIR/mock-splunk.log" 2>/dev/null))" >&2
  return 1
}

# stop_mock_splunk kills the mock if it's running. Idempotent.
stop_mock_splunk() {
  if [[ -n "${MOCK_SPLUNK_PID:-}" ]]; then
    kill "$MOCK_SPLUNK_PID" 2>/dev/null || true
    wait "$MOCK_SPLUNK_PID" 2>/dev/null || true
    unset MOCK_SPLUNK_PID MOCK_SPLUNK_PORT MOCK_SPLUNK_URL MOCK_SPLUNK_LOG
  fi
}
