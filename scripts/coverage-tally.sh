#!/usr/bin/env bash

set -euo pipefail

if [[ ! -f library.json ]]; then
  echo "error: must be run from the library root (library.json not found in $PWD)" >&2
  exit 2
fi
command -v yq >/dev/null 2>&1 || { echo "error: yq is required but not found in PATH" >&2; exit 127; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required but not found in PATH" >&2; exit 127; }

IFS=',' read -r -a siems <<< "${COVERAGE_SIEMS:-splunk}"
files=()
for siem in "${siems[@]}"; do
  if [[ ! "$siem" =~ ^[a-z0-9_-]+$ || ! -d "jobs/$siem" ]]; then
    echo "error: COVERAGE_SIEMS entry '$siem' has no jobs/$siem directory" >&2
    exit 2
  fi
  while IFS= read -r f; do
    files+=("$f")
  done < <(find "jobs/$siem" -type f -name '*.yaml' -print | LC_ALL=C sort)
done

if [[ ${#files[@]} -eq 0 ]]; then
  echo "error: no job files found for COVERAGE_SIEMS=${COVERAGE_SIEMS:-splunk}" >&2
  exit 1
fi

# One row per job; several jobs may validate the same detection.
yq ea -o=json -I=0 '{
    "path": filename,
    "test": .name,
    "id": .detection.id,
    "catalog": .detection.source,
    "detection_name": .detection.name,
    "techniques": (.mitre.techniques // []),
    "attack_scenarios": ([.workloads[]? | select(.expectation.expected == "alert")] | length),
    "benign_controls": ([.workloads[]? | select(.expectation.expected == "none")] | length)
  }' "${files[@]}" |
  jq -s --argjson siems "$(printf '%s\n' "${siems[@]}" | jq -R . | jq -s .)" '
    map(. + {siem: (.path | split("/")[1]), source: (.path | split("/")[2])})
    | (map(select(.id == null)) | length) as $undetected
    | map(select(.id != null))
    | (length) as $tests
    | group_by([.siem, .id])
    | map(sort_by(.path) | {
        siem: .[0].siem,
        source: .[0].source,
        id: .[0].id,
        catalog: .[0].catalog,
        title: (if .[0].catalog == "escu" then .[0].detection_name | sub("^ESCU - "; "") | sub(" - Rule$"; "") else .[0].detection_name end),
        tests: (map(.test) | sort),
        techniques: (map(.techniques[]) | unique),
        attack_scenarios: (map(.attack_scenarios) | add),
        benign_controls: (map(.benign_controls) | add)
      })
    | sort_by(.siem, .title)
    | {
        schema_version: 1,
        siems: $siems,
        totals: {
          detections: length,
          tests: $tests,
          tests_without_detection: $undetected,
          attack_scenarios: (map(.attack_scenarios) | add),
          benign_controls: (map(.benign_controls) | add),
          detections_with_benign_control: (map(select(.benign_controls > 0)) | length),
          techniques: (map(.techniques[]) | unique | length)
        },
        by_source: (group_by(.siem) | map({key: .[0].siem, value: (group_by(.source) | map({key: .[0].source, value: length}) | from_entries)}) | from_entries),
        detections: .
      }'
