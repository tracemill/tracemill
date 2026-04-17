#!/usr/bin/env bash
# Validate every event-type YAML in event-types/ against the installed tracemill CLI.
# Run from the library root. Aggregates all failures before exiting non-zero.
#
# Usage: scripts/validate-event-types.sh

set -euo pipefail

if [[ ! -f library.json ]]; then
  echo "error: must be run from the library root (library.json not found in $PWD)" >&2
  exit 2
fi

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

for f in event-types/**/*.yaml; do
  group "validate $f"
  if ! tracemill validate --event-type "${PWD}/${f}"; then
    failures+=("$f")
    annotate_file "$f" "event-type validation failed"
  fi
  endgroup
done

if (( ${#failures[@]} > 0 )); then
  annotate "${#failures[@]} event-type(s) failed validation"
  printf '  - %s\n' "${failures[@]}" >&2
  exit 1
fi
