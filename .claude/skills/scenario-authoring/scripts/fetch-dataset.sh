#!/usr/bin/env bash
# fetch-dataset.sh <url>
#
# Internal: implementation detail of the scenario-authoring skill
# (.claude/skills/scenario-authoring/SKILL.md). Not a stable CLI; flag names,
# output, and exit codes may change without notice.
#
# Downloads a dataset blob to .cache/scenario-authoring/attack_data/<sha256>,
# preserving the original file extension. Prints the cache path.
#
# Idempotent in the content-addressed sense: the URL is always re-fetched,
# but identical content produces the same sha256 and the same cache path,
# so repeated invocations don't multiply files in the cache. The temp
# download is discarded when the sha already exists. (The redundant fetch
# is acceptable for the few-MB attack_data files this targets; switching
# to a URL→sha lookup would lose content-drift detection.)
#
# Deps: curl, sha256sum (macOS: shasum).
set -euo pipefail

# Preflight: curl is hard-required; either sha256sum or shasum must exist.
command -v curl >/dev/null 2>&1 || {
  echo "fetch-dataset.sh: required command 'curl' not found in PATH" >&2
  exit 127
}
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "fetch-dataset.sh: neither 'sha256sum' (Linux) nor 'shasum' (macOS) found in PATH" >&2
  exit 127
fi

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <url>" >&2
  exit 2
fi

URL="$1"
CACHE_DIR="${SCENARIO_AUTHORING_CACHE:-.cache/scenario-authoring}/attack_data"
mkdir -p "$CACHE_DIR"

# Strip any fragment/query suffix first so URLs like
# `file.json?token=abc` or `file.xml#section` still preserve their original
# extension when matched against the whitelist below.
URL_PATH="${URL%%#*}"
URL_PATH="${URL_PATH%%\?*}"

EXT=""
case "$URL_PATH" in
  *.log|*.xml|*.json|*.ndjson|*.jsonl|*.csv|*.txt) EXT=".${URL_PATH##*.}" ;;
esac

# Create the temp file inside $CACHE_DIR so the final `mv` is a same-filesystem
# atomic rename (avoids copy+unlink fallback when $TMPDIR is on a different
# filesystem than the cache dir).
tmp="$(mktemp "$CACHE_DIR/.fetch.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

curl -fsSL -o "$tmp" "$URL" || {
  echo "fetch-dataset.sh: failed to fetch $URL" >&2
  exit 1
}

# sha256sum on Linux; shasum on macOS.
if command -v sha256sum >/dev/null; then
  SHA="$(sha256sum "$tmp" | awk '{print $1}')"
else
  SHA="$(shasum -a 256 "$tmp" | awk '{print $1}')"
fi

OUT="$CACHE_DIR/${SHA}${EXT}"
if [[ -f "$OUT" ]]; then
  # Cache hit; no need to move.
  rm -f "$tmp"
else
  mv "$tmp" "$OUT"
fi
trap - EXIT
echo "$OUT"
