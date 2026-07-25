---
name: scenario-authoring
description: Use when authoring tracemill scenarios and validation jobs from a sample telemetry dataset (xml/json/ndjson/kv/admon/text), optionally guided by a detection rule (v1 supported format: Splunk SPL). Produces schema-validated, fidelity-checked scenario and job YAML for supported event types (aws.cloudtrail@v1, windows.wineventlog@v1, o365.management@v1, azure.monitor.aad@v1, gcp.audit@v1, aws.asl@v1). Works entirely with the local tracemill CLI; no account or network needed.
---

# scenario-authoring: dataset -> validated scenarios and jobs

Turn a sample telemetry dataset into one or more tracemill scenarios --
and optionally a validation job -- schema-validated and fidelity-checked
against the dataset, using only the `tracemill` CLI.

Run everything from the project root so the working directory
(`.cache/scenario-authoring/`) lands in the project.

## Scope and inputs

Inputs:

- **Sample dataset** (required): a local file or URL. Supported
  formats: `xml`, `json`, `ndjson`, `kv`, `admon`, `text`. Binary formats
  (evtx, pcap) are rejected -- ask the user to convert to a text
  export and re-invoke.
- **Detection rule** (optional): guides load-bearing-field
  identification, attack/benign categorization, job volumetrics, and
  job placement. v1 supported format: Splunk SPL. A rule in any other
  form -- Sigma, KQL, vendor-console exports, prose descriptions -- is
  welcome as conversational context, but no detection profile is built
  from it and no rule-derived expectations are claimed.
- **Target surface**: the dataset must map to an existing library
  event type (`aws.cloudtrail@v1`, `windows.wineventlog@v1`,
  `o365.management@v1`, `azure.monitor.aad@v1`, `gcp.audit@v1`,
  `aws.asl@v1`; list with
  `tracemill list event-types`). No clean match -> abort: adding event
  types is a separate authoring task, out of scope here.

Outputs: scenario YAML drafts (and optionally a job YAML), validated by
`tracemill validate` and fidelity-checked against the dataset. See
"Working directories and output destination" for where they land.

Out of scope: creating event types, installing or modifying SIEM rules
or configuration, and per-event SIEM correlation tuning -- these need
platform access this skill does not assume.

## Glossary

- **Master sample** -- the promoted representative event for one kept
  category; source of truth for scenario field values and the
  fidelity oracle.
- **Kept sample** -- a sample categorized `attack-positive`,
  `attack-positive-variant`, or `benign-control` (i.e., not noise).
- **Detection profile** -- the normalized result of statically
  analyzing a detection rule in a supported format (contract below).
- **Load-bearing field** -- a native event field the rule filters or
  groups on; the scenario must reproduce it exactly.
- **Fidelity verdict** -- `compare-fidelity.sh`'s `pass` / `warn` /
  `fail` judgment of a rendered event against its master sample.
- **Content ID** -- the stable library-wide identifier of a scenario
  or job (see the library README).
- **Pool YAML** -- a reusable value-pool file consumed by jobs (see
  `references/job-authoring.md`).
- **`mitre:` block** -- a scenario's MITRE ATT&CK mapping block (see
  `references/engine-capabilities.md`).

## Hard rules

1. **ASCII-only authored content.** Every byte you author into
   scenario / job / pool YAML or Markdown must be 7-bit ASCII: `--`
   for em-dash, straight quotes, `...` for ellipsis, `->` for arrows.
   Sole exception: a field value copied verbatim from a master sample,
   where the non-ASCII byte is part of fidelity. Check each file:

   ```bash
   LC_ALL=C grep -nP '[^\x00-\x7F]' <file>
   ```

   Empty output = clean.

2. **Authored content is standalone and vendor-agnostic.** Every
   description, comment, tag, and file name in authored content must
   read as self-contained to someone who has only that file. Never
   reference: the detection rule or its source (rule names, rule field
   names, query fragments, upstream URLs or UUIDs), "the dataset" or
   "the sample", local file paths (`.cache/...`, home directories),
   this skill or its steps and scripts, or session artifacts (run IDs,
   timestamps, hostnames, usernames). MAY reference: the modeled
   security behavior in plain prose, the `mitre:` block, state
   variables by name, stable public documentation URLs, and other
   content by content ID.

3. **Never read a dataset in full.** Datasets can be MB- to GB-scale;
   use bounded reads (`head`, `wc -l`) and `extract-events.sh`
   for all summarization and sample extraction. Do not hand-roll
   awk/sed/jq/yq pipelines over the raw dataset (targeted reads of
   extracted single-event samples are fine). If the dataset fits none of
   the supported formats, abort with the step-2 sniff output -- do not
   paper over with a one-off extractor.

## Detection profile contract

When a detection rule arrives in a supported format, build a detection
profile -- the single normalized object every downstream step
(categorization, scenario state hardcoding, job authoring) consumes.
Downstream steps read the profile, never the raw rule.

```yaml
siem: splunk                  # inferred target SIEM; always user-confirmed
load_bearing_fields:          # native event paths + values the rule keys on,
  - path: eventName           #   mapped from the rule's naming layer
    value: DeleteTrail        #   (e.g. Splunk CIM) to native event paths
group_by: [sourceIPAddress]   # aggregation tuple; omit if none
threshold: "count > 9"        # volumetric predicate; omit if none
time_window: 10m              # aggregation window; omit if none
```

Nothing SIEM-specific may appear in the contract itself: field paths
are native event payload paths, never the SIEM's normalized naming.
All format knowledge lives in per-format detection modules; v1 ships
`references/detections/splunk-spl.md` (SPL static analysis: filter and
field extraction, stats/tstats aggregation semantics, CIM-to-native
mapping), and new formats add sibling modules in that directory. A
rule in a format with no module gets no profile -- conversational
context only.

## Workflow

The skill's scripts live in its `scripts/` directory. Define the
prefix once -- relative to the library checkout (or wherever the
skill is installed) -- and use it for every script invocation below:

```bash
SA=.claude/skills/scenario-authoring
```

All intermediate artifacts land under `.cache/scenario-authoring/`;
nothing outside it is written until the user confirms an output
destination. When starting a fresh authoring run, clear stale
`samples/`, `masters/`, `drafts/`, and `generated/` first -- leftovers
from a prior run would mix with this run's artifacts and corrupt
categorization and fidelity.

### 1. Fetch and cache the dataset

A local file is used in place. For a URL:

```bash
"$SA"/scripts/fetch-dataset.sh <url>
```

Stdout is a content-addressed cache path (identical content never
duplicates). Use the printed path in every later step.

### 2. Format-sniff

Three bounded commands; interpret the output:

```bash
file <path> && head -n 5 <path> && wc -l <path>
```

Decide: `xml` | `json` | `ndjson` | `kv` | `text`. Binary -> abort
with "convert to a text format and re-invoke". If the decision is
ambiguous, `extract-events.sh` also accepts `--format auto`.

### 3. Compute cardinality

Pick the categorization key -- the field whose distinct values separate
event kinds:

| Dataset shape | Key |
|---|---|
| Windows Event Log XML (incl. Sysmon channels) | `System/EventID` |
| Windows Event Log text-kv | `EventCode` |
| AWS CloudTrail (JSON `Records[]` or NDJSON) | `eventName` |
| Microsoft 365 Management Activity (JSON `Records[]` or NDJSON) | `Operation` |
| Microsoft Entra ID / Azure AD Monitor (JSON `records[]` or NDJSON) | `category` (then categorize sign-in success/failure within SignInLogs by `properties.resultType` / `properties.status.errorCode`) |
| Google Cloud Audit Logs (bare Cloud Audit LogEntry; a Splunk-indexed sample is `data`-wrapped -- drop that wrapper when authoring) | `protoPayload.methodName` (the audited API method distinguishes event kinds; `data.protoPayload.methodName` in a Splunk-indexed sample) |
| Amazon Security Lake CloudTrail (OCSF API Activity JSON, one object per event; NDJSON for multiple records) | `api.operation` (the field that distinguishes one API Activity from another) |

For anything else, propose a key and confirm it with the user. Then:

```bash
"$SA"/scripts/extract-events.sh --dataset <path> --format <fmt> --key <key> --mode summary
```

Output is JSON `{format, total, key, groups: [{key, count}, ...]}` --
record it for the final report (step 13).

### 4. Extract per-group samples

```bash
"$SA"/scripts/extract-events.sh --dataset <path> --format <fmt> --key <key> \
  --mode samples --out .cache/scenario-authoring/samples/<dataset-slug>/
```

`<dataset-slug>` is the dataset filename without its extension,
kebab-cased (for a URL, its basename). Writes one representative event
per distinct key value; stdout is JSON `[{key, sample_path}, ...]`. Key characters outside `A-Za-z0-9._-` are
sanitized; collision-prone keys get a checksum suffix.

### 5. Build the detection profile (optional)

Only when a detection rule was supplied in a supported format. Load the
matching module (`references/detections/splunk-spl.md` for SPL) and
statically analyze the rule text into the profile contract above.

**Confirm the inferred `siem` with the user** before it steers job
placement or expectations. For SPL, `"$SA"/scripts/extract-spl-groupby.sh
"<spl>"` can cross-check the group-by tuple against a live Splunk
parser (needs `SPLUNK_URL` / `SPLUNK_AUTH` in env; skip when unset).

Unsupported format or prose: no profile. Use the text as context for
judgment calls only; step 13 covers how the final report records this.

### 6. Categorize samples

Read each group's sample bounded (`head -n 20`, targeted `yq` paths)
and label it:

- `attack-positive` -- the behavior a detection should fire on
- `attack-positive-variant` -- an alternate path to the same effect
- `benign-control` -- legitimate activity a detection must not fire on
- `noise` -- discarded

With a profile, match each sample against `load_bearing_fields`;
without one, categorize conversationally. Each kept sample gets a slug:
kebab-case, max 30 chars, naming the security behavior, not the event
ID (`lsass-dump-procdump`, not `eid10-lsass-access`). **Present the
categorization table to the user and get confirmation** before
proceeding.

### 7. Promote masters

```bash
mkdir -p .cache/scenario-authoring/masters/
cp .cache/scenario-authoring/samples/<dataset-slug>/<group>.<ext> \
   .cache/scenario-authoring/masters/<slug>.<ext>
```

One master per kept category, renamed to its slug. Masters are the
source of truth for the field values embedded in scenario state and
for the fidelity check.

### 8. Author scenario drafts

Read `references/engine-capabilities.md` first -- `gen.*` / `fn.*` /
`ref.*` forms, per-surface idioms, and the authoring checklist. Then
write one draft per kept category to
`.cache/scenario-authoring/drafts/scenarios/<taxonomy-path>/<slug>.yaml`,
following the library taxonomy (library README): cloud =
`{provider}/{service}` where service is the API's owner (CloudTrail
`eventSource` minus `.amazonaws.com`), not the delivery channel;
endpoint = `{platform}/{log-source}/{event-category}`.

- Bind only the fields in the profile's `group_by` (they may be
  lifted to job state later, step 11); hardcode every other
  load-bearing field's value in scenario `state:`. Environmental
  fields (timestamps, GUIDs, request IDs, source IPs) use `gen.*`.
- Threshold / volumetric detections: model ONE event in the scenario;
  volume belongs to the job (step 11).
- Tags per "Tagging taxonomy"; apply the Hard rules to every file.

### 9. Validate drafts

```bash
tracemill validate --scenario <draft-path>
```

Add `--library <path-to-library-checkout>` when authoring against a
checkout. On schema failure, print the validator's error verbatim and
ask the user whether to retry-author or abort -- never silently patch:
a schema error can mask a deeper modeling problem.

### 10. Fidelity check

Schema validation proves the draft parses; this proves the rendered
event matches the master. Per draft, use the surface extension for
symmetry with the master (`.xml` Windows Event Log, `.log` Windows
admon, `.json` CloudTrail). The rendered output follows the surface
(XML, sectioned KV, or NDJSON), and the comparator auto-detects it, so
never pass `--format` manually:

In the fidelity scripts, `admon` means the multiline ActiveDirectory wire
format: a record begins with a column-zero `dcName=`, may
contain section headings, and ends at the admon sentinel, timestamp
preamble, or next column-zero `dcName=`. Generic `kv` remains the
one-event-per-line format; it is rejected by fidelity with an explicit
diagnostic rather than interpreted with admon framing.

```bash
G=.cache/scenario-authoring/generated
tracemill --library <checkout> run scenario <draft-path> > "$G/<slug>.<ext>"
"$SA"/scripts/compare-fidelity.sh --master .cache/scenario-authoring/masters/<slug>.<ext> --generated "$G/<slug>.<ext>" --load-bearing "<tokens>" > "$G/<slug>.fidelity.json"
```

The redirected fidelity JSON is the evidence for the final report;
read the verdict from it.

`--load-bearing` is a comma-separated token list derived from the
profile's `load_bearing_fields` (or your own analysis). Three token
modes, freely mixed:

- **exact** (default): a master dot-path, wildcards `[*]` / `{*}`
  allowed -- `eventName`, `EventData.QueryName`,
  `requestParameters.organizationArn[*]`. Generated value must equal
  the master's.
- **glob membership**: `<path>~<glob>[|<glob>...]` -- e.g.
  `eventName~Describe*|List*|Get*`; every generated record must match
  one glob (`*` any run, `?` one char).
- **aggregate distinct-count**: `dc(<path>)<op><n>`, op in `>` `>=`
  `<` `<=` `==` -- e.g. `dc(eventName)>50`; evaluated across the whole
  generated burst. Do not use on single-emit renders -- volume is
  validated at the job level.

When a rule's load-bearing field or value does NOT appear in the
master sample (the rule keys on something the captured dataset lacks),
do not use an exact token -- the comparator flags
`load_bearing_master_missing` and fails. Use a glob token
(`<field>~<value>`) instead, which validates the generated side only,
and say so in the final report (step 13).

Verdicts: `pass` (load-bearing matches, coverage >= 80%) -> proceed.
`warn` (load-bearing matches, coverage < 80%) -> proceed only when
each `missing_in_generated` entry is justified (upstream artifacts the
scenario should not reproduce, fields the event-type schema does not
model); otherwise patch and re-run. `fail` (a load-bearing field
missing or mismatched -- the detection would not fire) -> patch and
re-run; never proceed on `fail`.

**Then show the diff.** The verdict is a machine judgment; the operator
still needs to eyeball what the scenario actually emits against the
captured event. As soon as a draft reaches a `pass` or `warn` verdict,
diff its rendered event against the master, reusing the render you just
judged so the diff reflects the exact event behind the verdict. **Paste
the diff output verbatim into your visible reply inside a fenced ```diff
block -- "show" means the operator reads the actual diff in the message,
not a prose summary of it and not output left in a tool-call result their
client may collapse. A characterization ("environmental churn only") may
accompany the rendered diff but never replaces it.** This
lives here, not in the final report, so that any caller who runs the
fidelity step -- a direct run or a wrapping skill -- always surfaces it
(a `fail` is patched and re-run first; its diff appears on the re-run
that clears the fail):

```bash
"$SA"/scripts/diff-against-master.sh \
  --master .cache/scenario-authoring/masters/<slug>.<ext> \
  --generated "$G/<slug>.<ext>"
```

The diff canonicalizes formatting (indentation, JSON key order, or admon
timestamp/section/line-ending layout) and shows every remaining field
difference flat, unsuppressed. Environmental fields
(`gen.*` timestamps, GUIDs, request IDs, source IPs) differ on every render
by design -- that churn is expected, not a defect, and on a `warn` it also
helps you judge whether the `missing_in_generated` entries are acceptable.
The pass / warn / fail signal remains the fidelity verdict above, not this
diff: present the diff as a human-readable confirmation of what the scenario
emits. If a *non-environmental* field differs unexpectedly, that is a
fidelity finding (patch the draft and re-run steps 9-10), not something to
reconcile from the diff. The diff shows only the first event of each side
(the master is one sample; a multi-emit render is a burst); byte-level
entity drift is out of its scope -- the `raw_encoding_drift` check in
the fidelity JSON above owns that.

### 11. Author a validation job (optional)

Read `references/job-authoring.md` -- the generic job shape: the
top-level `name` (customer-facing Test name), workloads, state and
bindings, pools, loop/matrix, expectations. Drafts go to
`.cache/scenario-authoring/drafts/jobs/...`.

- **With a detection profile**: the job targets
  `jobs/<siem>/<taxonomy-path>/<job-slug>.yaml`, mirroring the scenario
  taxonomy. Workload expectations follow categorization:
  attack-positive and variants -> `expectation.expected: alert`,
  benign-control -> `expectation.expected: none` (a workload without an
  expectation validates vacuously). For `threshold` / `time_window`
  profiles, use the volumetric pattern: `loop: N` with N strictly
  greater than the threshold, binding the `group_by` tuple through job
  state (the step-8 bind rule) so the burst collapses into one group.
- **Without a profile**: author a generic orchestration job,
  project-local, with no detection expectations claimed.

Whether or not a job was authored, now confirm the output destination
with the user and move the finished drafts out of `.cache/` (see
"Working directories and output destination"). Validate the job only
AFTER the move: its content-ID scenario references resolve from the
destination content root, not from `.cache/` (validating there fails
with "content not found"). With the destination as the working
directory, run `tracemill --library <checkout> validate --job
<dest-job-path>`. The order is: move, then validate the job from its
post-move path.

This skill authors and locally validates content; it does not run jobs
against a live SIEM. Detection validation against a target is out of
scope here.

### 12. Follow established patterns

Analyze established library patterns for jobs and job workloads and make
sure the content you author follows them:

- **state management**: a job keeps centralized state across workloads
    and drives workload state to make the output coherent, e.g., make
    actor, IP addresses, account ids, computer hostnames coordinated
    across workloads a job drives
- **idiomatic defaults**: refer to similar scenarios and jobs for
    established patterns in setting field defaults, e.g., account ids,
    actor names, IP addresses, computer hostnames, etc.

**Always** review the authored scenarios and jobs for adherence to these patterns before
submitting them.

### 13. Final report

Each successfully-authored scenario (schema-validated in step 9, fidelity
`pass` or accepted `warn` in step 10) already had its generated-vs-master
diff shown in step 10, where the diff is produced. The final report
collects that evidence into one place; it does not re-run the diff.

Close out with a report containing:

- the dataset cardinality summary (step 3 JSON);
- the per-sample categorization table with slugs (step 6);
- the detection profile, or an explicit statement that none was built
  and no rule-derived expectations are claimed;
- `tracemill validate` results for every draft (steps 9 and 11);
- fidelity verdicts per scenario, with the justification for any
  accepted `warn` (step 10);
- the generated-vs-master diff for each successfully-authored scenario
  (produced in step 10);
- the job path and SIEM placement, when a job was authored;
- the output destination the user confirmed.

## Working directories and output destination

```text
.cache/scenario-authoring/
  samples/<dataset-slug>/   # step 4: one sample per group
  masters/                  # step 7: promoted master samples
  drafts/                   # steps 8, 11: scenario and job YAML drafts
  generated/                # step 10: rendered events + fidelity reports
```

The dataset cache itself is managed by `fetch-dataset.sh`, which prints
the cached path. Everything under `.cache/` is disposable.

Once the destination is confirmed (end of step 11), move drafts out
of `.cache/` to one of:

- **Default -- project-local content**: copy finished files into the
  project's own content tree (e.g. `./scenarios/...`, `./jobs/...`)
  and run them by file path or through the CLI's content layering
  (project content takes precedence over user content, which takes
  precedence over the installed library).
- **Alternative -- contribute to a library checkout**: place files per
  the library taxonomy (see the library README), run
  `tracemill validate --dir .` from the checkout root, and open a PR.

## Tagging taxonomy

Tags are an index over dimensions the file path and `mitre:` block do
not already encode. Every tag must fit a closed dimension below; if
none applies, omit `tags:` entirely (most jobs end up here).

| Dimension | When | Values |
|---|---|---|
| Identifier | only when the path does not already encode it | `eid<N>` for Windows event logs -- the path uses semantic category names (`process-access`), so the numeric tag bridges to `tracemill list scenarios --tags eid10`. Skip when the filename slug IS the identifier (`delete-trail.yaml` already encodes `delete-trail`). |
| Threat | optional, multi | kebab-case campaign / actor / incident (`3cx`, `apt29`, `lockbit`) -- only when the entry mirrors a named campaign, not generic technique simulation. |
| Tool | optional, multi | kebab-case adversary tool (`procdump`, `mimikatz`) -- only when the entry emits artifacts unique to that tool (image path, distinctive command line). |
| CVE | optional, multi | `cve-YYYY-NNNNN`, lowercase prefix (`cve-2023-29059`) -- only when the entry exercises behavior tied to that assigned CVE. |

Examples and counter-examples:

| Entry | Tags | Why |
|---|---|---|
| `scenarios/windows/sysmon/dns-query/3cx-ioc-dns-query` | `[eid22, 3cx, cve-2023-29059]` | identifier + named campaign + assigned CVE |
| `scenarios/windows/sysmon/process-access/lsass-dump-procdump` | `[eid10, procdump]` | identifier + tool-unique artifacts |
| `scenarios/aws/cloudtrail/delete-trail` | omitted | path already encodes the slug; no threat/tool/CVE |
| `jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts` | omitted | typical job: no cross-cutting dimension |
| any | never `aws`, `iam`, `splunk`, `logon`, ... | provider / service / SIEM / category live in the path |
| any | never tactics, technique IDs, `attack`, `benign` | the `mitre:` block encodes them; its presence (attack) or absence (benign) is the role signal |
| any | never `auth`, `network`, `evasion`, ... | free-form hints collapse into MITRE vocabulary |
