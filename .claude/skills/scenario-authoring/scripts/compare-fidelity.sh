#!/usr/bin/env bash
# compare-fidelity.sh --master <path> --generated <path>
#                    [--format <auto|xml|json>]
#                    [--load-bearing <comma-sep-paths>]
#
# Compare a master event (raw upstream sample) against a generated event
# (rendered by `tracemill run scenario`) and emit a JSON fidelity report.
#
# Supported event surfaces:
#   - xml  — Windows EventLog (Sysmon, Security audit). `EventData.Data[]`
#            is collapsed from a Name-keyed array of `{+@Name, +content}`
#            entries into a Name-keyed map so per-field comparison is
#            order-independent and dot-paths are human-readable
#            (e.g. `EventData.QueryName` rather than
#            `EventData.Data.4.+content`).
#   - json — JSON / NDJSON (CloudTrail and any future JSON-shaped surface).
#            Accepts: a single JSON object, a `{"Records":[...]}` envelope
#            (first record used — matches the upstream CloudTrail shape),
#            a top-level array (first element used), or NDJSON (first
#            non-blank record used). The generated side is normally an
#            NDJSON line emitted by the JSONLFormatter sink.
#
# `--format` is per-comparison; both master and generated are interpreted
# in the same mode. `auto` (default) inspects the first non-blank byte of
# each file independently — `<` → xml, anything else → json — so an XML
# master can be compared against an XML generated event and a JSON master
# against a JSON generated event without an explicit flag.
#
# --load-bearing tokens (comma-separated) come in three modes:
#   - exact (default): a dot-path, optionally with [*]/{*} wildcards
#     (e.g. `eventName`, `requestParameters.organizationArn[*]`). The value
#     in the single master record must equal the value in the (first)
#     generated record. This is what literal-filter SPL needs.
#   - glob membership: `<path>~<glob>[|<glob>...]`
#     (e.g. `eventName~Describe*|List*|Get*`). EVERY generated record's value
#     at <path> must match one of the |-separated globs (`*` = any run, `?` =
#     any single char). Models SPL prefix/glob filters.
#   - distinct-count cardinality: `dc(<path>)<op><n>`, op ∈ > >= < <= == =
#     (e.g. `dc(eventName)>50`, `dc(userIdentity.userName)==1`). The distinct
#     count of <path> across the WHOLE generated burst must satisfy the
#     predicate. Models `stats dc(x) ... | where` thresholds and single
#     group-by keys.
# Glob and cardinality tokens reason over every generated record (the full
# burst), not just the first; exact tokens compare the single master record.
# Modes may be mixed in one --load-bearing list.
#
# Output JSON shape (stdout):
#   {
#     "master_path": "...",
#     "generated_path": "...",
#     "master_field_count": 24,
#     "generated_field_count": 23,
#     "generated_event_count": 53,
#     "coverage_pct": 95.8,
#     "missing_in_generated": ["System.Security.+@UserID", ...],
#     "extra_in_generated": [...],
#     "value_diffs": [
#       {"path": "...", "master": "...", "generated": "...", "load_bearing": false},
#       ...
#     ],
#     "load_bearing": ["eventName~Describe*|List*|Get*", "dc(eventName)>50"],
#     "load_bearing_master_missing": [...],
#     "load_bearing_aggregate": [
#       {"kind": "glob", "path": "eventName", "globs": [...],
#        "checked": 53, "violations": 0, "match": true},
#       {"kind": "cardinality", "path": "eventName", "op": ">",
#        "threshold": 50, "distinct": 53, "match": true}
#     ],
#     "load_bearing_match": true,
#     "verdict": "pass" | "warn" | "fail"
#   }
#
# Verdict rules:
#   - fail: an exact --load-bearing field is missing from the generated event
#           OR differs from the master, an exact field is absent from the
#           master itself (load_bearing_master_missing), or any glob/cardinality
#           aggregate token is unsatisfied. The detection SPL filters/aggregates
#           on these, so a mismatch means the savedsearch won't fire.
#   - warn: load-bearing checks all pass, but coverage_pct < 80 (the scenario
#           is missing a significant fraction of master fields — may still
#           validate end-to-end but won't look realistic in the SIEM).
#   - pass: load-bearing checks all pass and coverage_pct >= 80.
#
# Internal: implementation detail of the scenario-authoring skill
# (.claude/skills/scenario-authoring/SKILL.md). Not a stable CLI; flag names,
# output JSON shape, and exit codes may change without notice.
#
# Deps: yq (Mike Farah, Go), jq.
set -euo pipefail

for cmd in yq jq head sed; do
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
      # Allow an explicit empty value — callers may legitimately have
      # zero load-bearing fields (the SKILL.md documents passing "" for
      # that case). Only require that the value arg is *present*: the
      # last-arg case ($# < 2) means the user wrote `--load-bearing`
      # with nothing after it, which is an authoring mistake.
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
  auto|xml|json) ;;
  *) echo "compare-fidelity.sh: unsupported format: $FORMAT (expected auto|xml|json)" >&2; exit 2 ;;
esac

# detect_format inspects the first non-blank byte of $1 and returns "xml"
# (leading `<`) or "json" (anything else). This is a coarser sniff than
# extract-events.sh — that script also distinguishes json from ndjson via
# `jq -s 'length'`. Compare-fidelity does not need that distinction:
# flatten_json transparently handles both shapes via `limit(2; inputs)`.
detect_format() {
  local f="$1" head_bytes head_trimmed
  head_bytes="$(head -c 200 "$f" 2>/dev/null || true)"
  head_trimmed="$(printf '%s' "$head_bytes" | sed -E $'s/^(\xef\xbb\xbf|[[:space:]])+//')"
  if [[ "$head_trimmed" == "<"* ]]; then
    echo "xml"
  else
    echo "json"
  fi
}

# Convert Windows EventLog XML to a flat dot-path → value map. Steps:
#   1. yq parses XML to JSON (attributes prefixed with `+@`, text with `+content`).
#   2. Strip `+@xmlns` namespace declarations (cosmetic; differs by source).
#   3. Unwrap the top-level `Event` envelope.
#   4. Collapse `EventData.Data[]` (a Name-keyed array of `{+@Name, +content}`)
#      into `EventData = {<Name>: <content>, ...}` so paths are stable across
#      files where the array order differs.
#   5. Flatten to a `{dot.path: value}` map keyed by leaf path.
flatten_xml() {
  local file="$1"
  yq -p xml -o json '.' "$file" \
    | jq '
        walk(if type == "object" then with_entries(select(.key != "+@xmlns")) else . end)
        | if has("Event") then .Event else . end
        | if .EventData and (.EventData.Data | type == "array") then
            .EventData = (.EventData.Data | map({(.["+@Name"]): (.["+content"] // "")}) | add)
          elif .EventData and (.EventData.Data | type == "object") then
            .EventData = {(.EventData.Data["+@Name"]): (.EventData.Data["+content"] // "")}
          else . end
      ' \
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

# Convert JSON / NDJSON to a flat dot-path → value map.
#
# Input shapes accepted (all reduce to a single event object before flatten):
#   - single JSON object       → use as-is
#   - {"Records":[...]}        → first record (raw upstream CloudTrail shape)
#   - top-level array          → first element
#   - NDJSON (>1 top-level doc)→ first record (matches the master-events
#                                 cache layout for NDJSON datasets and the
#                                 generated event from JSONLFormatter — one
#                                 event per line)
#
# Detection uses `jq -n '[limit(2; inputs)] | length'`, which reads at most
# two top-level JSON values via `inputs` rather than slurping the whole
# file. `jq -s` would buffer everything into an array first; this is
# bounded regardless of file size.
#
# After the reduce, the event is validated as a non-empty object — `[]`,
# `{"Records":[]}`, scalars, and NDJSON-of-scalars all collapse to `null`
# or a non-object value and would otherwise flatten into a degenerate
# (often empty) dot-path map that the verdict logic would silently accept.
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

flatten() {
  local file="$1" fmt="$2"
  case "$fmt" in
    xml)  flatten_xml  "$file" ;;
    json) flatten_json "$file" ;;
    *) echo "compare-fidelity.sh: unsupported format: $fmt" >&2; return 2 ;;
  esac
}

# Flatten EVERY record of a JSON/NDJSON file into an array of dot-path maps
# (one map per event), feeding the aggregate load-bearing modes
# (glob membership, distinct-count cardinality) which reason over the whole
# generated burst rather than a single representative record. Each top-level
# doc is expanded the same way flatten_json reduces a single one: a top-level
# array yields its elements, a `{"Records":[...]}` envelope yields its records,
# and a bare object yields itself. NDJSON yields one event per line.
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

# Resolve the per-side format. In `auto` we sniff each file independently
# and require the two sides agree; an XML master with a JSON generated
# (or the reverse) almost always means the caller pointed at the wrong
# file, and silently flattening each via its own parser would produce a
# zero-overlap report that looks like a real coverage gap. Hard-fail
# with a diagnostic so the operator notices. Explicit `--format xml|json`
# bypasses the detect-and-compare step — the user has asked for that
# format on both sides, so trust them and let the parser surface any
# mismatch as a parse error.
m_format="$FORMAT"
g_format="$FORMAT"
if [[ "$FORMAT" == "auto" ]]; then
  m_format="$(detect_format "$MASTER")"
  g_format="$(detect_format "$GENERATED")"
  if [[ "$m_format" != "$g_format" ]]; then
    echo "compare-fidelity.sh: master format ($m_format, $MASTER) and generated format ($g_format, $GENERATED) differ — pass --format to override or check the file paths" >&2
    exit 2
  fi
fi

m_flat="$(flatten "$MASTER"    "$m_format")"
g_flat="$(flatten "$GENERATED" "$g_format")"

# g_all is the per-record flattened view of the ENTIRE generated burst, used by
# the aggregate load-bearing modes (glob membership, distinct-count
# cardinality). Only computed when --load-bearing actually contains a glob (~)
# or cardinality (dc(...)) token; for exact-only or empty lists we reuse the
# already-flattened first record, avoiding the cost of reading large NDJSON
# bursts in the common non-volumetric case.
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

if [[ "$has_aggregate_tokens" -eq 1 && "$g_format" == "json" ]]; then
  g_all="$(flatten_json_all "$GENERATED")"
else
  g_all="[$g_flat]"
fi

# Compute the diff and verdict in jq. `master_keys`/`generated_keys` are
# treated as sets; missing/extra are set differences; value_diffs are the
# intersection where the values differ. Load-bearing match is the single
# load_bearing value compared after normalising whitespace.
jq -n \
  --argjson m "$m_flat" \
  --argjson g "$g_flat" \
  --argjson gall "$g_all" \
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
      load_bearing:                $lb,
      load_bearing_master_missing: $lb_missing_in_master,
      load_bearing_aggregate:      $aggregate,
      load_bearing_match:          (($lb_missing_in_master | length) == 0 and ($exact_fail | not) and ($aggregate_fail | not)),
      verdict:               (
        if ($lb_missing_in_master | length) > 0 then "fail"
        elif $exact_fail then "fail"
        elif $aggregate_fail then "fail"
        elif $coverage < 80 then "warn"
        else "pass"
        end
      )
    }
  '
