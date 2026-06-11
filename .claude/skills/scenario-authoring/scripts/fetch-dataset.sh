#!/usr/bin/env bash
# fetch-dataset.sh <url>
# Internal helper for the scenario-authoring skill; not a stable CLI. Downloads a URL to a content-addressed cache; prints the cache path.
set -euo pipefail

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

# Strip fragment/query so `file.json?token=abc` still yields `.json` as the extension.
URL_PATH="${URL%%#*}"
URL_PATH="${URL_PATH%%\?*}"

EXT=""
case "$URL_PATH" in
  *.log|*.xml|*.json|*.ndjson|*.jsonl|*.csv|*.txt) EXT=".${URL_PATH##*.}" ;;
esac

# mktemp inside $CACHE_DIR so the final `mv` is an atomic same-filesystem rename.
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
  rm -f "$tmp"
else
  mv "$tmp" "$OUT"
fi
trap - EXIT
echo "$OUT"
