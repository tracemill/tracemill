#!/usr/bin/env bash

_ADMON_SUPPORT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ADMON_RECORDS_JQ="$_ADMON_SUPPORT_DIR/admon-records.jq"

structural_prefix_format() {
  LC_ALL=C awk '
    BEGIN {
      bom = sprintf("%c%c%c", 239, 187, 191)
      found = 0
    }

    {
      line = $0
      while (1) {
        sub(/^[[:space:]]+/, "", line)
        if (substr(line, 1, 3) == bom) {
          line = substr(line, 4)
        } else {
          break
        }
      }
      if (line == "") {
        next
      }
      found = 1
      first = substr(line, 1, 1)
      if (first == "<") {
        print "xml"
      } else if (first == "{" || first == "[") {
        print "json"
      } else {
        print "other"
      }
      exit
    }

    END {
      if (!found) {
        print "other"
      }
    }
  ' "$1"
}

admon_probe_file() {
  LC_ALL=C awk '
    function is_timestamp(value, lower) {
      lower = tolower(value)
      return value ~ /^[0-9][0-9]?\/[0-9][0-9]?\/([0-9][0-9]|[0-9][0-9][0-9][0-9])$/ \
        || lower ~ /^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](\.[0-9]+)?([ \t]+(am|pm))?$/ \
        || lower ~ /^[0-9][0-9]?\/[0-9][0-9]?\/([0-9][0-9]|[0-9][0-9][0-9][0-9])[ \t]+[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](\.[0-9]+)?([ \t]+(am|pm))?$/
    }

    BEGIN { result = 1; started = 0 }

    {
      line = $0
      while (!started && substr(line, 1, 3) == sprintf("%c%c%c", 239, 187, 191)) {
        line = substr(line, 4)
      }
      sub(/\r$/, "", line)
      structural = line
      sub(/[ \t]+$/, "", structural)

      if (structural ~ /^[ \t]*$/) {
        next
      }
      if (!started) {
        if (structural == "---splunk-admon-end-of-event---" || is_timestamp(structural)) {
          next
        }
        if (structural ~ /^dcName=[^ \t]*$/) {
          started = 1
          next
        }
        exit
      }
      unindented = structural
      sub(/^[ \t]+/, "", unindented)
      if (structural == "---splunk-admon-end-of-event---" \
          || is_timestamp(structural) \
          || line ~ /^[ \t]/ \
          || unindented ~ /^[^=:\t\r\n][^=:\t\r\n]*:$/) {
        result = 0
        exit
      }
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
        while (!started && substr(line, 1, 3) == sprintf("%c%c%c", 239, 187, 191)) {
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
