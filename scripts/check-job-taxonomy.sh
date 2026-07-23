#!/usr/bin/env bash
# Enforce the public job naming and optional authored Detection contract.

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

normalize_name() {
  LC_ALL=C awk '
    {
      for (i = 1; i <= NF; i++) {
        if (normalized != "") {
          normalized = normalized " "
        }
        normalized = normalized tolower($i)
      }
    }
    END { print normalized }
  ' <<< "$1"
}

job_files=()
while IFS= read -r f; do
  job_files+=("$f")
done < <(find jobs -type f -name '*.yaml' -print | LC_ALL=C sort)
normalized_names=()
content_ids=()
failure_count=0

for f in "${job_files[@]}"; do
  content_id="${f%.yaml}"
  name_tag="$(yq -r '.name | tag' "$f")"
  raw_name="$(yq -r '.name // ""' "$f")"
  normalized_name=""

  if [[ "$name_tag" == "!!str" ]]; then
    normalized_name="$(normalize_name "$raw_name")"
  fi
  if [[ -z "$normalized_name" ]]; then
    annotate_file "$f" "missing or blank Test name"
    ((failure_count += 1))
  else
    for ((i = 0; i < ${#normalized_names[@]}; i++)); do
      if [[ "$normalized_name" == "${normalized_names[$i]}" ]]; then
        annotate_file "$f" "normalized Test name \"$normalized_name\" collides between content IDs ${content_ids[$i]} and $content_id"
        ((failure_count += 1))
      fi
    done
    normalized_names+=("$normalized_name")
    content_ids+=("$content_id")
  fi

  workload_detection_count="$(
    yq -r '[.workloads[]? | .expectation | select(tag == "!!map" and has("detection"))] | length' "$f"
  )"
  if [[ "$workload_detection_count" != "0" ]]; then
    annotate_file "$f" "workload-level expectation.detection is not allowed ($workload_detection_count declaration(s))"
    ((failure_count += 1))
  fi

  detection_tag="$(yq -r '.detection | tag' "$f")"
  if [[ "$detection_tag" != "!!null" && "$detection_tag" != "!!map" ]]; then
    annotate_file "$f" "top-level detection must be a single mapping when present"
    ((failure_count += 1))
    continue
  fi

  if [[ "$(yq -r '.detection.source // ""' "$f")" == "escu" ]]; then
    detection_name_tag="$(yq -r '.detection.name | tag' "$f")"
    detection_name="$(yq -r '.detection.name // ""' "$f")"
    if [[ "$detection_name_tag" != "!!str" ||
          ! "$detection_name" =~ ^ESCU\ -\ (.+)\ -\ Rule$ ||
          ! "${BASH_REMATCH[1]}" =~ ^[^[:space:]](.*[^[:space:]])?$ ]]; then
      annotate_file "$f" 'ESCU detection.name must use exact native title form "ESCU - <name> - Rule"'
      ((failure_count += 1))
    fi
  fi
done

if (( failure_count > 0 )); then
  annotate "job taxonomy lint failed with $failure_count error(s)"
  exit 1
fi

echo "job taxonomy: ${#job_files[@]} job(s) named, normalized-unique, and compliant with the optional authored Detection contract"
