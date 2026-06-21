#!/usr/bin/env bash
# Enforce that every Splunk job resolves to a detection. A job resolves when it
# has a job-level `detection:` block (the default, applied to all workloads) OR
# every workload that carries an `expectation:` has its own
# `expectation.detection`. Observation-only workloads (no expectation) need none.
# This is the provenance gate backing regression/coverage: a Splunk job exists
# to validate a specific detection, so that detection must be recorded.
#
# Run from the library root.
#
# Usage: scripts/check-detection-coverage.sh

set -euo pipefail

if [[ ! -f library.json ]]; then
  echo "error: must be run from the library root (library.json not found in $PWD)" >&2
  exit 2
fi
command -v yq >/dev/null 2>&1 || { echo "error: yq is required but not found in PATH" >&2; exit 127; }

ci=false
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  ci=true
fi
annotate_file() { $ci && echo "::error file=$1::$2" || echo "FAIL: $1 ($2)" >&2; }
annotate()      { $ci && echo "::error::$*"         || echo "$*" >&2; }

shopt -s globstar nullglob
failures=()

for f in jobs/splunk/**/*.yaml; do
  # job-level detection covers all workloads
  if [[ "$(yq '.detection != null' "$f")" == "true" ]]; then
    continue
  fi
  # otherwise every workload with an expectation must carry its own detection
  uncovered="$(yq '[.workloads[]? | select(.expectation != null) | select(.expectation.detection == null)] | length' "$f")"
  if [[ "$uncovered" != "0" ]]; then
    failures+=("$f")
    annotate_file "$f" "no resolvable detection: ${uncovered} workload(s) with an expectation lack expectation.detection and the job has no top-level detection:"
  fi
done

if (( ${#failures[@]} > 0 )); then
  annotate "${#failures[@]} Splunk job(s) missing a resolvable detection (add a job-level detection: block or expectation.detection per workload)"
  printf '  - %s\n' "${failures[@]}" >&2
  exit 1
fi

echo "detection coverage: all Splunk jobs resolve to a detection"
