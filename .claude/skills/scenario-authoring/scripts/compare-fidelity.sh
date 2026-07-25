#!/usr/bin/env bash
# Compare a master event against a generated event and emit a JSON fidelity
# report (coverage_pct, load_bearing_match, verdict pass/warn/fail).
# Internal to the scenario-authoring skill; not a stable CLI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMON_RECORDS_JQ="$SCRIPT_DIR/admon-records.jq"

for cmd in yq jq head sed grep awk; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "compare-fidelity.sh: required command '$cmd' not found in PATH" >&2
    exit 127
  }
done

MASTER=""
GENERATED=""
LOAD_BEARING=""
FORMAT="auto"

require_flag_value() {
  local flag="$1" next="${2-}"
  if [[ -z "$next" || "$next" == --* ]]; then
    echo "compare-fidelity.sh: $flag requires a value" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --master)     require_flag_value "$1" "${2-}"; MASTER="$2";    shift 2 ;;
    --generated)  require_flag_value "$1" "${2-}"; GENERATED="$2"; shift 2 ;;
    --format)     require_flag_value "$1" "${2-}"; FORMAT="$2";    shift 2 ;;
    --load-bearing)
      # Callers may pass "" for zero load-bearing fields; require the arg to be
      # present (missing entirely means authoring mistake, not intentional empty).
      if [[ $# -lt 2 ]]; then
        echo "compare-fidelity.sh: --load-bearing requires a value (pass \"\" for none)" >&2
        exit 2
      fi
      LOAD_BEARING="$2"
      shift 2
      ;;
    *) echo "compare-fidelity.sh: unknown flag: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$MASTER"    ]] || { echo "compare-fidelity.sh: --master required"    >&2; exit 2; }
[[ -n "$GENERATED" ]] || { echo "compare-fidelity.sh: --generated required" >&2; exit 2; }
[[ -f "$MASTER"    ]] || { echo "compare-fidelity.sh: master not found: $MASTER"       >&2; exit 2; }
[[ -f "$GENERATED" ]] || { echo "compare-fidelity.sh: generated not found: $GENERATED" >&2; exit 2; }

case "$FORMAT" in
  auto|xml|json|admon) ;;
  *) echo "compare-fidelity.sh: unsupported format: $FORMAT (expected auto|xml|json|admon)" >&2; exit 2 ;;
esac

detect_format() {
  local f="$1" head_bytes head_trimmed
  head_bytes="$(head -c 200 "$f" 2>/dev/null || true)"
  head_trimmed="$(printf '%s' "$head_bytes" | sed -E $'s/^(\xef\xbb\xbf|[[:space:]])+//')"
  if [[ "$head_trimmed" == "<"* ]]; then
    echo "xml"
  elif [[ "$head_trimmed" == "{"* || "$head_trimmed" == "["* ]]; then
    echo "json"
  elif printf '%s' "$head_trimmed" | grep -Eq '^dcName=.' \
       || grep -aEq '^dcName=.+' "$f"; then
    echo "admon"
  elif grep -aEq '^[[:blank:]]*[A-Za-z0-9_-]+=' "$f"; then
    echo "unsupported-kv"
  else
    echo "json"
  fi
}

# A scenario with multiple `emit` steps renders one file containing sibling
# <Event> roots; yq -p xml -o json collapses those to {"Event":[ev0,ev1,...]}
# and a single event to {"Event":{...}}. This normalizes both to an ARRAY of
# event objects so a burst flattens the same way one event does. It also strips
# xmlns and collapses the Name-keyed EventData.Data[] into a map so per-field
# paths are stable regardless of array order across files.
_XML_EVENTS_JQ='
  walk(if type == "object" then with_entries(select(.key != "+@xmlns")) else . end)
  | (if type == "object" and has("Event") then .Event else . end)
  | (if type == "array" then . else [.] end)
  | map(
      if .EventData and (.EventData.Data | type == "array") then
        .EventData = (.EventData.Data | map({(.["+@Name"]): (.["+content"] // "")}) | add)
      elif .EventData and (.EventData.Data | type == "object") then
        .EventData = {(.EventData.Data["+@Name"]): (.EventData.Data["+content"] // "")}
      else . end
    )
'

# Reduce one event object to a flat {dot.path: value} map. Empty objects/arrays
# are preserved as "{}"/"[]" placeholders so missing-field checks can see them.
_XML_DOTMAP_JQ='
  [ paths as $p
    | (getpath($p)) as $v
    | select(
        ($v | type) as $t
        | $t == "string" or $t == "number" or $t == "boolean" or $t == "null"
          or ($t == "object" and ($v | length) == 0)
          or ($t == "array"  and ($v | length) == 0)
      )
    | {key: ($p | map(tostring) | join(".")),
       value: (
         if   ($v | type) == "object" then "{}"
         elif ($v | type) == "array"  then "[]"
         else ($v | tostring)
         end
       )}
  ] | from_entries
'

# First event only — the single-record master/coverage/exact comparison,
# mirroring flatten_json's first-record selection.
flatten_xml() {
  local file="$1"
  yq -p xml -o json '.' "$file" \
    | jq "$_XML_EVENTS_JQ"' | .[0] // {} | '"$_XML_DOTMAP_JQ"
}

# Every event flattened into an array of dot-path maps; used by glob and
# cardinality tokens that must reason over the full generated burst. Mirrors
# flatten_json_all.
flatten_xml_all() {
  local file="$1"
  yq -p xml -o json '.' "$file" \
    | jq "$_XML_EVENTS_JQ"' | map('"$_XML_DOTMAP_JQ"')'
}

# Uses limit(2; inputs) rather than jq -s to avoid buffering large NDJSON bursts.
flatten_json() {
  local file="$1" event
  event="$(jq -nc '
      [limit(2; inputs)] as $docs
      | if ($docs | length) == 0 then error("no JSON values")
        else
          ($docs[0]) as $first
          | if ($first | type) == "array" then $first[0]
            elif ($first | type) == "object"
                 and ($first | has("Records"))
                 and (($first.Records | type) == "array")
              then $first.Records[0]
            else $first
            end
        end
    ' "$file" 2>/dev/null)" || {
    echo "compare-fidelity.sh: cannot parse JSON/NDJSON from $file" >&2
    return 1
  }
  printf '%s' "$event" \
    | jq -e 'type == "object" and (length > 0)' >/dev/null 2>&1 || {
    echo "compare-fidelity.sh: $file did not yield a non-empty event object" >&2
    return 1
  }
  printf '%s' "$event" \
    | jq '[
        paths as $p
        | (getpath($p)) as $v
        | select(
            ($v | type) as $t
            | $t == "string" or $t == "number" or $t == "boolean" or $t == "null"
              or ($t == "object" and ($v | length) == 0)
              or ($t == "array"  and ($v | length) == 0)
          )
        | {key: ($p | map(tostring) | join(".")),
           value: (
             if   ($v | type) == "object" then "{}"
             elif ($v | type) == "array"  then "[]"
             else ($v | tostring)
             end
           )}
      ] | from_entries'
}

admon_records() {
  local file="$1" out
  out="$(jq -Rn -f "$ADMON_RECORDS_JQ" "$file" 2>&1)" || {
    echo "compare-fidelity.sh: cannot parse ActiveDirectory admon KV from $file: $out" >&2
    return 1
  }
  printf '%s' "$out"
}

flatten_admon_kv() {
  local file="$1"
  admon_records "$file" | jq '.[0].fields'
}

flatten_admon_kv_all() {
  local file="$1"
  admon_records "$file" | jq 'map(.fields)'
}

flatten() {
  local file="$1" fmt="$2"
  case "$fmt" in
    xml)  flatten_xml  "$file" ;;
    json) flatten_json "$file" ;;
    admon) flatten_admon_kv "$file" ;;
    *) echo "compare-fidelity.sh: unsupported format: $fmt" >&2; return 2 ;;
  esac
}

# Flattens every record in the file into an array of dot-path maps; used by
# glob and cardinality tokens that must reason over the full generated burst.
flatten_json_all() {
  local file="$1" all
  all="$(jq -nc '
    [ inputs
      | if type == "array" then .[]
        elif (type == "object" and has("Records") and (.Records | type == "array"))
          then .Records[]
        else . end
    ] as $records
    | if all($records[]; type == "object" and (length > 0)) then
        $records
      else
        error("expanded record is not a non-empty object")
      end
    | map(
        . as $ev
        | [ paths as $p
            | ($ev | getpath($p)) as $v
            | select(
                ($v | type) as $t
                | $t == "string" or $t == "number" or $t == "boolean" or $t == "null"
                  or ($t == "object" and ($v | length) == 0)
                  or ($t == "array"  and ($v | length) == 0)
              )
            | {key: ($p | map(tostring) | join(".")),
               value: (
                 if   ($v | type) == "object" then "{}"
                 elif ($v | type) == "array"  then "[]"
                 else ($v | tostring)
                 end
               )}
          ] | from_entries
      )
  ' "$file" 2>/dev/null)" || {
    echo "compare-fidelity.sh: cannot parse JSON/NDJSON (all records) from $file" >&2
    return 1
  }
  printf '%s' "$all"
}

# In auto mode, mismatched formats (XML master vs JSON generated) almost always
# indicate wrong file paths; hard-fail rather than produce a silently degenerate report.
m_format="$FORMAT"
g_format="$FORMAT"
if [[ "$FORMAT" == "auto" ]]; then
  m_format="$(detect_format "$MASTER")"
  g_format="$(detect_format "$GENERATED")"
  if [[ "$m_format" == "unsupported-kv" || "$g_format" == "unsupported-kv" ]]; then
    echo "compare-fidelity.sh: generic key=value input is not supported by fidelity; use format admon for a sectioned ActiveDirectory record beginning with dcName=" >&2
    exit 2
  fi
  if [[ "$m_format" != "$g_format" ]]; then
    echo "compare-fidelity.sh: master format ($m_format, $MASTER) and generated format ($g_format, $GENERATED) differ — pass --format to override or check the file paths" >&2
    exit 2
  fi
fi

m_flat="$(flatten "$MASTER"    "$m_format")"
g_flat="$(flatten "$GENERATED" "$g_format")"

# Only pay the cost of reading the full NDJSON burst when an aggregate token
# (glob ~ or cardinality dc()) is actually present; exact-only lists reuse
# the already-flattened first record.
has_aggregate_tokens=0
if [[ -n "$LOAD_BEARING" ]]; then
  IFS=',' read -r -a _lb_tokens <<< "$LOAD_BEARING"
  for _tok in "${_lb_tokens[@]}"; do
    _tok="${_tok#"${_tok%%[! ]*}"}"  # ltrim
    if [[ "$_tok" == *"~"* || "$_tok" == dc\(* ]]; then
      has_aggregate_tokens=1
      break
    fi
  done
fi

if [[ "$has_aggregate_tokens" -eq 1 ]]; then
  case "$g_format" in
    json) g_all="$(flatten_json_all "$GENERATED")" ;;
    xml)  g_all="$(flatten_xml_all "$GENERATED")" ;;
    admon) g_all="$(flatten_admon_kv_all "$GENERATED")" ;;
  esac
else
  g_all="[$g_flat]"
fi

# Byte-level entity-encoding drift check (XML only). Splunk's byte-regex
# extraction indexes raw, undecoded bytes, so the generated file must use the
# same encoding of '>' as the master; the decoded-value comparison above is
# blind to this. Compared per <Data Name=...> field so a master that mixes
# forms across fields still gets each field checked against its own form;
# falls back to a document-global comparison for XML without <Data> elements.
raw_encoding_drift="[]"
if [[ "$m_format" == "xml" && "$g_format" == "xml" ]]; then
  # One line per <Data> field: "name<TAB>has_entity<TAB>has_literal",
  # flags OR-ed across occurrences of the same name.
  data_field_flags() {
    # grep exits 1 on zero matches; that is the legitimate "no <Data>
    # elements" case, not an error -- guard it so pipefail does not abort.
    { grep -oE "<Data Name=('[^']*'|\"[^\"]*\")>[^<]*" "$1" 2>/dev/null || true; } \
      | sed -E "s/^<Data Name='([^']*)'>/\1\t/; s/^<Data Name=\"([^\"]*)\">/\1\t/" \
      | awk -F'\t' '
          { name=$1; txt=substr($0, length(name)+2)
            if (txt ~ /&gt;/) e[name]=1
            if (txt ~ />/)   l[name]=1
            seen[name]=1 }
          END { for (n in seen) printf "%s\t%d\t%d\n", n, e[n]?1:0, l[n]?1:0 }'
  }
  m_fields="$(data_field_flags "$MASTER")"
  g_fields="$(data_field_flags "$GENERATED")"
  if [[ -n "$m_fields" && -n "$g_fields" ]]; then
    raw_encoding_drift="$(awk -F'\t' '
        NR==FNR { me[$1]=$2; ml[$1]=$3; next }
        ($1 in me) {
          if (me[$1] && !ml[$1] && $3) print $1 "\tentity\tliteral"
          else if (ml[$1] && !me[$1] && $2) print $1 "\tliteral\tentity"
        }' <(printf '%s\n' "$m_fields") <(printf '%s\n' "$g_fields") \
      | jq -R -s '[ split("\n")[] | select(length > 0) | split("\t")
          | {char: ">", field: .[0],
             detail: ("master encodes > as \(.[1]) in this field; generated uses \(.[2]) — Splunk indexes raw bytes, so detections keyed on the master byte form will not match")} ]')"
  else
    text_content() { sed -e 's/<[^>]*>//g' "$1"; }
    m_text="$(text_content "$MASTER")"
    g_text="$(text_content "$GENERATED")"
    drift=""
    if [[ "$m_text" == *"&gt;"* && "$m_text" != *">"* && "$g_text" == *">"* ]]; then
      drift="master encodes > as &gt; in element text content; generated emits a literal > — Splunk indexes raw bytes, so detections keyed on the entity form will not match"
    elif [[ "$m_text" == *">"* && "$m_text" != *"&gt;"* && "$g_text" == *"&gt;"* ]]; then
      drift="master emits a literal > in element text content; generated encodes it as &gt; — Splunk indexes raw bytes, so detections keyed on the literal form will not match"
    fi
    if [[ -n "$drift" ]]; then
      raw_encoding_drift="$(jq -n --arg d "$drift" '[{char: ">", detail: $d}]')"
    fi
  fi
fi

# Verdict logic lives in the jq below; see classify/glob_results/card_results.
jq -n \
  --argjson m "$m_flat" \
  --argjson g "$g_flat" \
  --argjson gall "$g_all" \
  --argjson raw_drift "$raw_encoding_drift" \
  --arg master_path "$MASTER" \
  --arg generated_path "$GENERATED" \
  --arg load_bearing "$LOAD_BEARING" \
  '
  # Translate a load-bearing pattern (may contain [*] or {*} wildcards) into
  # a regex that matches concrete flattened dot-paths. Concrete array indices
  # appear as numeric path segments (e.g. `requestParameters.organizationArn.0`),
  # so `[*]` translates to `\.[0-9]+` and `{*}` to `\.[^.]+`.
  #
  # Step 1: extract `[*]` / `{*}` wildcard tokens to placeholders that do not
  # collide with regex syntax.
  # Step 2: escape every regex metacharacter in what remains — XML attribute
  # paths like `System.Provider.+@Name` contain `+` (and other paths can
  # contain `*`, `?`, parens, braces etc.) and must be treated as literals.
  # Step 3: substitute the wildcard placeholders with their regex form.
  def pattern_to_regex(p):
    p
    | gsub("\\[\\*\\]"; "__ARR__")
    | gsub("\\{\\*\\}"; "__OBJ__")
    | gsub("(?<c>[.+*?^$|()\\[\\]{}\\\\])"; "\\\(.c)")
    | gsub("__ARR__"; "\\.[0-9]+")
    | gsub("__OBJ__"; "\\.[^.]+")
    | "^" + . + "$";

  # Return the subset of `paths` that match pattern `p`.
  def match_pattern(p; paths):
    paths | map(select(. | test(pattern_to_regex(p))));

  # Translate a shell-style glob (`*` = any run, `?` = any single char) into an
  # anchored regex. Every other metacharacter is escaped so it matches
  # literally; `*` and `?` are deliberately left out of the escape class so the
  # subsequent substitutions can expand them.
  def glob_to_regex($glob):
    $glob
    | gsub("(?<c>[.+^$|()\\[\\]{}\\\\])"; "\\\(.c)")
    | gsub("\\*"; ".*")
    | gsub("\\?"; ".")
    | "^" + . + "$";

  # Classify a load-bearing token into one of three modes:
  #   - cardinality: `dc(<path>)<op><n>` (op ∈ > >= < <= == =) — distinct count
  #     of <path> across the whole generated burst must satisfy the predicate.
  #   - glob: `<path>~<glob>[|<glob>...]` — every generated record value at
  #     <path> must match one of the |-separated globs.
  #   - exact: a dot-path (possibly with [*]/{*}) compared for literal equality
  #     against the single master record (legacy behaviour).
  def classify($t):
    if ($t | test("^dc\\([^)]+\\)\\s*(>=|<=|==|=|>|<)\\s*[0-9]+$")) then
      ($t | capture("^dc\\((?<path>[^)]+)\\)\\s*(?<op>>=|<=|==|=|>|<)\\s*(?<n>[0-9]+)$")) as $c
      | { kind: "cardinality",
          path: ($c.path | gsub("^\\s+|\\s+$"; "")),
          op: (if $c.op == "=" then "==" else $c.op end),
          threshold: ($c.n | tonumber) }
    elif ($t | test("~")) then
      ($t | index("~")) as $i
      | { kind: "glob",
          path: ($t[:$i] | gsub("^\\s+|\\s+$"; "")),
          globs: ($t[($i + 1):] | split("|") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))) }
    else
      { kind: "exact", pat: $t }
    end;

  ($m | keys) as $mkeys
  | ($g | keys) as $gkeys
  | (
      $load_bearing
      | split(",")
      | map(gsub("^\\s+|\\s+$"; ""))
      | map(select(length > 0))
    ) as $lb
  | ($lb | map(classify(.)))                            as $tokens
  | ($tokens | map(select(.kind == "exact") | .pat))    as $exacts
  | ($tokens | map(select(.kind == "glob")))            as $globs
  | ($tokens | map(select(.kind == "cardinality")))     as $cards
  | ($mkeys - $gkeys) as $missing
  | ($gkeys - $mkeys) as $extra
  | [
      $mkeys[]
      | select(($g[.] // null) != null and $g[.] != $m[.])
      | { path: .,
          master: $m[.],
          generated: $g[.],
          load_bearing: (
            . as $p
            | $exacts
            | map(. as $pat | match_pattern($pat; [$p]) | length > 0)
            | any
          ) }
    ] as $value_diffs
  | (
      # Exact patterns that match no concrete path in the master are flagged as
      # master-missing (the load-bearing field does not exist on either side).
      # Aggregate (glob/cardinality) tokens are validated against the generated
      # burst, not the single master record, so they are exempt.
      [ $exacts[]
        | . as $pat
        | select((match_pattern($pat; $mkeys) | length) == 0)
        | $pat
      ]
    ) as $lb_missing_in_master
  | (
      # For each exact pattern, every concrete master path it matches must also
      # exist in generated with an equal value.
      [ $exacts[]
        | . as $pat
        | match_pattern($pat; $mkeys)
        | .[]
        | select(($g[.] // null) == null or $g[.] != $m[.])
      ] | length > 0
    ) as $exact_fail
  | (
      # Glob membership: every generated record must carry the path AND its
      # value must match one of the token globs. A missing path or a
      # non-matching value counts as a violation.
      [ $globs[]
        | . as $tok
        | ( [ $gall[]
              | (.[$tok.path] // null) as $v
              | select(
                  $v == null
                  or (([ $tok.globs[] | . as $gl | ($v | test(glob_to_regex($gl))) ] | any) | not)
                )
            ] | length ) as $violations
        | { kind: "glob",
            path: $tok.path,
            globs: $tok.globs,
            checked: ($gall | length),
            violations: $violations,
            match: ($violations == 0 and ($gall | length) > 0) }
      ]
    ) as $glob_results
  | (
      # Distinct-count cardinality across the generated burst (nulls/absent
      # values excluded), compared against the token threshold. An empty burst
      # never matches: a detection cannot fire with zero events, so a token
      # like dc(x)<=0 / dc(x)==0 must not be satisfied by a degenerate
      # (empty or non-rendering) generated file (mirrors the glob check).
      [ $cards[]
        | . as $tok
        | ( [ $gall[] | (.[$tok.path] // null) | select(. != null and . != "null") ] | unique | length ) as $dc
        | { kind: "cardinality",
            path: $tok.path,
            op: $tok.op,
            threshold: $tok.threshold,
            distinct: $dc,
            match: (
              ($gall | length) > 0
              and (
                if   $tok.op == ">"  then $dc >  $tok.threshold
                elif $tok.op == ">=" then $dc >= $tok.threshold
                elif $tok.op == "<"  then $dc <  $tok.threshold
                elif $tok.op == "<=" then $dc <= $tok.threshold
                else $dc == $tok.threshold
                end
              )
            ) }
      ]
    ) as $card_results
  | ($glob_results + $card_results) as $aggregate
  | ([ $aggregate[] | select(.match | not) ] | length > 0) as $aggregate_fail
  | (
      if ($mkeys | length) == 0 then 100.0
      else (100.0 * (($mkeys | length) - ($missing | length)) / ($mkeys | length))
      end
    ) as $coverage
  | {
      master_path:                 $master_path,
      generated_path:              $generated_path,
      master_field_count:          ($mkeys | length),
      generated_field_count:       ($gkeys | length),
      generated_event_count:       ($gall | length),
      coverage_pct:                (($coverage * 10 | round) / 10),
      missing_in_generated:        $missing,
      extra_in_generated:          $extra,
      value_diffs:                 $value_diffs,
      raw_encoding_drift:          $raw_drift,
      load_bearing:                $lb,
      load_bearing_master_missing: $lb_missing_in_master,
      load_bearing_aggregate:      $aggregate,
      load_bearing_match:          (($lb_missing_in_master | length) == 0 and ($exact_fail | not) and ($aggregate_fail | not)),
      verdict:               (
        if ($lb_missing_in_master | length) > 0 then "fail"
        elif $exact_fail then "fail"
        elif $aggregate_fail then "fail"
        elif ($raw_drift | length) > 0 then "fail"
        elif $coverage < 80 then "warn"
        else "pass"
        end
      )
    }
  '
