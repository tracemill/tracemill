#!/usr/bin/env bash

_ADMON_SUPPORT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ADMON_RECORDS_JQ="$_ADMON_SUPPORT_DIR/admon-records.jq"

admon_probe_file() {
  LC_ALL=C awk '
    function is_timestamp(value, lower) {
      lower = tolower(value)
      return value ~ /^[0-9][0-9]?\/[0-9][0-9]?\/([0-9][0-9]|[0-9][0-9][0-9][0-9])$/ \
        || lower ~ /^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](\.[0-9]+)?([ \t]+(am|pm))?$/ \
        || lower ~ /^[0-9][0-9]?\/[0-9][0-9]?\/([0-9][0-9]|[0-9][0-9][0-9][0-9])[ \t]+[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](\.[0-9]+)?([ \t]+(am|pm))?$/
    }

    BEGIN { result = 1 }

    {
      line = $0
      if (NR == 1 && substr(line, 1, 3) == sprintf("%c%c%c", 239, 187, 191)) {
        line = substr(line, 4)
      }
      sub(/\r$/, "", line)
      structural = line
      sub(/[ \t]+$/, "", structural)

      if (structural ~ /^[ \t]*$/ || structural == "---splunk-admon-end-of-event---" || is_timestamp(structural)) {
        next
      }
      if (structural ~ /^dcName=[^ \t]*$/) {
        result = 0
      }
      exit
    }

    END { exit result }
  ' "$1"
}

admon_records() {
  local file="$1" out caller
  caller="${0##*/}"
  out="$(jq -Rn -f "$_ADMON_RECORDS_JQ" "$file" 2>&1)" || {
    echo "$caller: cannot parse ActiveDirectory admon KV from $file: $out" >&2
    return 1
  }
  printf '%s' "$out"
}

admon_first_record() {
  local file="$1" out caller
  caller="${0##*/}"
  out="$(
    LC_ALL=C awk '
      function is_timestamp(value, lower) {
        lower = tolower(value)
        return value ~ /^[0-9][0-9]?\/[0-9][0-9]?\/([0-9][0-9]|[0-9][0-9][0-9][0-9])$/ \
          || lower ~ /^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](\.[0-9]+)?([ \t]+(am|pm))?$/ \
          || lower ~ /^[0-9][0-9]?\/[0-9][0-9]?\/([0-9][0-9]|[0-9][0-9][0-9][0-9])[ \t]+[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](\.[0-9]+)?([ \t]+(am|pm))?$/
      }

      {
        raw = $0
        line = raw
        if (NR == 1 && substr(line, 1, 3) == sprintf("%c%c%c", 239, 187, 191)) {
          line = substr(line, 4)
        }
        sub(/\r$/, "", line)
        structural = line
        sub(/[ \t]+$/, "", structural)

        if (started && (structural == "---splunk-admon-end-of-event---" || is_timestamp(structural) || line ~ /^dcName=/)) {
          exit
        }
        print raw
        if (line ~ /^dcName=/) {
          started = 1
        }
      }
    ' "$file" | jq -Rn -f "$_ADMON_RECORDS_JQ" /dev/stdin 2>&1
  )" || {
    echo "$caller: cannot parse first ActiveDirectory admon record from $file: $out" >&2
    return 1
  }
  printf '%s' "$out"
}
