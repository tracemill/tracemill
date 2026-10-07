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
files=(scenarios/**/*.yaml jobs/**/*.yaml)
jobs="${COMPILE_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

# Each dry-run writes its own log and exit code, so the report below stays in file order.
dry_run() {
  local f="$1" key
  key="${f//\//__}"
  tracemill run --dry-run "${f%.yaml}" > "$out/$key.log" 2>&1
  echo $? > "$out/$key.rc"
}
export -f dry_run
export out

printf '%s\0' "${files[@]}" | xargs -0 -P "$jobs" -I{} bash -c 'dry_run "$1"' _ {}

failures=()
for f in "${files[@]}"; do
  key="${f//\//__}"
  group "dry-run ${f%.yaml}"
  cat "$out/$key.log"
  if [[ "$(cat "$out/$key.rc" 2>/dev/null)" != 0 ]]; then
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
