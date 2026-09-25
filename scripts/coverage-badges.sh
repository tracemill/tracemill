#!/usr/bin/env bash
# Write shields.io endpoint badges from a coverage.json.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <coverage.json> <out-dir>" >&2
  exit 2
fi
coverage="$1"
out="$2"

if [[ "$(jq -r '.schema_version' "$coverage")" != "1" ]]; then
  echo "error: unsupported coverage schema_version in $coverage" >&2
  exit 2
fi

mkdir -p "$out"
badge() {
  jq -n --arg label "$1" --arg message "$2" \
    '{schemaVersion: 1, label: $label, message: $message, color: "0d9488"}' > "$out/$3"
}
badge "Splunk ESCU detections" "$(jq '[.by_source.splunk // {} | .[]] | add // 0' "$coverage")" splunk-detections.json
badge "attack scenarios" "$(jq '.totals.attack_scenarios' "$coverage")" attack-scenarios.json
badge "ATT&CK techniques" "$(jq '.totals.techniques' "$coverage")" attack-techniques.json
