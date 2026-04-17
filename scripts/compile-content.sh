#!/usr/bin/env bash
# Dry-run every scenario and job YAML against the installed tracemill CLI.
# Exercises the full parse -> compile -> execute path without emitting events
# (SummarySink + ManualClock). Run from the library root. Aggregates all
# failures before exiting non-zero.
#
# Scenarios and jobs are invoked as content IDs (e.g. scenarios/aws/foo/bar)
# with TRACEMILL_LIBRARY set to PWD, mirroring real user invocation against
# an installed library.
#
# Usage: scripts/compile-content.sh

set -euo pipefail

if [[ ! -f library.json ]]; then
  echo "error: must be run from the library root (library.json not found in $PWD)" >&2
  exit 2
fi

export TRACEMILL_LIBRARY="$PWD"

ci=false
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  ci=true
fi

group()    { $ci && echo "::group::$*"    || echo "=== $* ==="; }
endgroup() { $ci && echo "::endgroup::"   || true; }
annotate_file() { $ci && echo "::error file=$1::$2" || echo "FAIL: $1 ($2)" >&2; }
annotate()      { $ci && echo "::error::$*"         || echo "$*" >&2; }

shopt -s globstar nullglob
failures=()

for f in scenarios/**/*.yaml jobs/**/*.yaml; do
  id="${f%.yaml}"
  group "dry-run $id"
  if ! tracemill run --dry-run "$id"; then
    failures+=("$f")
    annotate_file "$f" "dry-run failed"
  fi
  endgroup
done

if (( ${#failures[@]} > 0 )); then
  annotate "${#failures[@]} file(s) failed dry-run"
  printf '  - %s\n' "${failures[@]}" >&2
  exit 1
fi
