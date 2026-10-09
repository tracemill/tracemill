#!/usr/bin/env bash
# Render every scenario and job (`tracemill validate --dir`) without emitting
# events. Run from the library root. scenarios/ and jobs/ rather than `.`:
# scripts/tests/fixtures holds deliberately invalid files.
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

# Older CLIs only parse in `validate --dir`, which would pass content that
# fails at render; refuse them rather than check less than CI does.
min="$(jq -r '.min_cli_version' library.json)"
have="$(tracemill version | awk '/^Version:/ {print $2}')"
if [[ "$have" != "dev" && "$(printf '%s\n%s\n' "$min" "$have" | sort -V | head -1)" != "$min" ]]; then
  echo "error: tracemill $have is older than min_cli_version $min" >&2
  exit 2
fi

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

status=0
for dir in scenarios jobs; do
  $ci && echo "::group::validate $dir" || echo "=== validate $dir ==="
  tracemill validate --dir "$dir" 2> "$out/$dir.err" || status=1
  cat "$out/$dir.err" >&2
  $ci && echo "::endgroup::" || true
  if $ci; then
    sed -nE 's/^([^ ]+) \.\.\. FAIL \((.*)$/::error file='"$dir"'\/\1.yaml::\2/p' "$out/$dir.err"
    # Unparsable YAML aborts discovery before any per-file line is printed.
    sed -nE 's/^Error: .*read content file "([^"]+)": (.*)$/::error file=\1::\2/p' "$out/$dir.err"
  fi
done
exit "$status"
