# Scenario authoring method

Turn a sample telemetry dataset into one or more tracemill scenarios --
and optionally a validation job -- schema-validated and fidelity-checked
against the dataset.

This method is tool-neutral: it names operations (summarize, sample,
validate, compare fidelity, diff), not commands. Your surface layer
supplies the concrete command or tool for each step, where intermediate
files live, the content-ID namespace, and where finished content goes.

Guides, read when a step points at them:

- `engine-capabilities.md` -- expression forms, per-surface idioms,
  library conventions, the authoring checklist.
- `job-authoring.md` -- job semantics: anatomy, evaluation, pools,
  expectations, the `detection:` block, volumetric jobs.
- `detections/splunk-spl.md` -- the Splunk SPL detection module.

## Scope and inputs

Inputs:

- **Sample dataset** (required). Supported formats: `xml`, `json`,
  `ndjson`, `kv`, `text`. Binary formats (evtx, pcap) are rejected --
  ask the user to convert to a text export. Every format supports
  summarizing, sampling, and categorization, but the fidelity
  comparison reads only XML and JSON masters (including NDJSON and
  JSON `Records[]` exports): a `kv` or `text` master gets no fidelity
  verdict and no structural diff. Tell the user so up front, and either
  ask for an XML or JSON export of the same events or compare the
  load-bearing fields against the render by hand (Fidelity step).
- **Detection rule** (optional): guides load-bearing-field
  identification, attack/benign categorization, job volumetrics, and
  job targeting. v1 supported format: Splunk SPL. A rule in any other
  form -- Sigma, KQL, vendor-console exports, prose descriptions -- is
  welcome as conversational context, but no detection profile is built
  from it and no rule-derived expectations are claimed.
- **Target surface**: the dataset must map to an existing library
  event type (`aws.cloudtrail@v1`, `windows.wineventlog@v1`,
  `o365.management@v1`, `azure.monitor.aad@v1`, `gcp.audit@v1`,
  `aws.asl@v1`). No clean match -> abort: adding event types is a
  separate authoring task, out of scope here.

Outputs: scenario YAML (and optionally a job YAML), schema-validated
and fidelity-checked against the dataset (for a `kv` or `text`
dataset, compared by hand instead -- see above).

Out of scope: creating event types, installing or modifying SIEM rules
or configuration, and per-event SIEM correlation tuning.

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
- **Fidelity verdict** -- the fidelity comparison's `pass` / `warn` /
  `fail` judgment of a rendered event against its master sample.
- **Content ID** -- the stable identifier of a scenario or job; its
  namespace is set by your surface.
- **Pool** -- a reusable value source consumed by jobs (see
  `job-authoring.md`).
- **`mitre:` block** -- a scenario's MITRE ATT&CK mapping block (see
  `engine-capabilities.md`).

## Hard rules

1. **ASCII-only authored content.** Every byte you author into
   scenario / job / pool YAML or Markdown must be 7-bit ASCII: `--`
   for em-dash, straight quotes, `...` for ellipsis, `->` for arrows.
   Sole exception: a field value copied verbatim from a master sample,
   where the non-ASCII byte is part of fidelity. Check every authored
   file for non-ASCII bytes before promoting it.

2. **Authored content is standalone and vendor-agnostic.** Every
   description, comment, tag, and file name in authored content must
   read as self-contained to someone who has only that file. Never
   reference: the detection rule or its source (rule names, rule field
   names, query fragments, upstream URLs or UUIDs), "the dataset" or
   "the sample", local file paths (working directories, caches, home
   directories), this method, its steps or its tools, or session
   artifacts (run IDs, timestamps, hostnames, usernames). MAY
   reference: the modeled security behavior in plain prose, the
   `mitre:` block, state variables by name, stable public
   documentation URLs, and other content by content ID.

## Detection profile contract

When a detection rule arrives in a supported format, build a detection
profile -- the single normalized object every downstream step
(categorization, scenario state hardcoding, job authoring) consumes.
Downstream steps read the profile, never the raw rule, for rule
semantics. The rule's provenance -- its catalog title and stable id
when a catalog entry backs it, otherwise its title and rule text -- is
recorded alongside the profile for the job's `detection:` block (see
`job-authoring.md`).

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
`detections/splunk-spl.md` (SPL static analysis: filter and field
extraction, stats/tstats aggregation semantics, CIM-to-native mapping),
and new formats add sibling modules in that directory. A rule in a
format with no module gets no profile -- conversational context only.

## Steps

Start each authoring run from a clean working area: leftover samples,
masters, drafts, or renders from a prior run would mix with this run's
artifacts and corrupt categorization and fidelity.

### 1. Summarize

Pick the categorization key -- the field whose distinct values
separate event kinds:

| Dataset shape | Key |
|---|---|
| Windows Event Log XML (incl. Sysmon channels) | `System/EventID` |
| Windows Event Log text-kv | `EventCode` |
| AWS CloudTrail (JSON `Records[]` or NDJSON) | `eventName` |
| Microsoft 365 Management Activity (JSON `Records[]` or NDJSON) | `Operation` |
| Microsoft Entra ID / Azure AD Monitor (JSON `records[]` or NDJSON) | `category` (then categorize sign-in success/failure within SignInLogs by `properties.resultType` / `properties.status.errorCode`) |
| Google Cloud Audit Logs (bare Cloud Audit LogEntry; a Splunk-indexed sample is `data`-wrapped -- drop that wrapper when authoring) | `protoPayload.methodName` (the audited API method distinguishes event kinds; `data.protoPayload.methodName` in a Splunk-indexed sample) |
| Amazon Security Lake CloudTrail (OCSF API Activity JSON, one object per event; NDJSON for multiple records) | `api.operation` (the field that distinguishes one API Activity from another) |

For anything else, propose a key and confirm it with the user. Then
summarize the dataset by that key: its format, total event count, and
the count per category. Record the summary for the report.

### 2. Sample

Extract one representative event (the first) per category, one file
per category.

### 3. Profile (optional)

Only when a detection rule was supplied in a supported format. Load the
matching module (`detections/splunk-spl.md` for SPL) and statically
analyze the rule text into the profile contract above.

**Confirm the inferred `siem` with the user** before it steers job
targeting or expectations. For SPL, the group-by reduction (module
section 4) can cross-check the tuple when a Splunk instance is
reachable; disagreement between it and your reading is a stop-and-ask.

Unsupported format or prose: no profile. Use the text as context for
judgment calls only; the Report step covers how this is recorded.

### 4. Categorize

Read each category's sample (bounded, targeted reads) and label it:

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

### 5. Promote masters

One master per kept category, named by its slug. Masters are the
source of truth for the field values embedded in scenario state and
for the fidelity check.

### 6. Author scenarios

Read `engine-capabilities.md` first -- `gen.*` / `fn.*` / `ref.*`
forms, per-surface idioms, and the authoring checklist. Then write one
draft per kept category, at a content ID that follows the library
taxonomy: cloud = `{provider}/{service}` where service is the API's
owner (CloudTrail `eventSource` minus `.amazonaws.com`), not the
delivery channel; endpoint = `{platform}/{log-source}/{event-category}`.

- Expose as state variables the fields in the profile's `group_by`
  (the job pins them through job state, in the Job step) and any
  field a distinct-count `threshold` counts (the job varies it from a
  pool or matrix); hardcode every other load-bearing field's value in
  scenario `state:`. Environmental
  fields (timestamps, GUIDs, request IDs, source IPs) use `gen.*`.
- Threshold / volumetric detections: model ONE event in the scenario;
  volume belongs to the job.
- Tags per "Tagging taxonomy"; apply the Hard rules to every file.

### 7. Validate

Schema-validate every draft. On failure, show the validator's error
verbatim and ask the user whether to retry-author or abort -- never
silently patch: a schema error can mask a deeper modeling problem.

### 8. Fidelity

Schema validation proves the draft parses; this proves the rendered
event matches the master. Render each draft and compare the render
against its master, passing the load-bearing tokens. Keep the
comparison report as evidence for the Report step.

**`kv` or `text` master: no verdict.** The comparison reads only XML
and JSON masters, so it cannot judge a `kv` or `text` master, and
there is no structural diff either. Prefer an XML or JSON export of
the same events when the user can supply one, and re-run from Sample
with it. Otherwise render the draft and check each load-bearing field
by hand in every rendered event, not just the first, with the same
semantics as the tokens below (exact value equal to the master's,
glob matched by every record). Show the human the master, the first
rendered event, and that field-by-field comparison, and state plainly
that no fidelity verdict exists for this scenario.

**Load-bearing tokens** -- a comma-separated list derived from the
profile's `load_bearing_fields` (or your own analysis). Three modes,
freely mixed:

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
do not use an exact token -- the comparison flags
`load_bearing_master_missing` and fails. Use a glob token
(`<field>~<value>`) instead, which validates the generated side only,
and say so in the report.

**Reading the verdict:**

- `pass` (load-bearing matches, coverage >= 80%) -> proceed.
- `warn` (load-bearing matches, coverage < 80%) -> proceed only when
  each `missing_in_generated` entry is justified (upstream artifacts
  the scenario should not reproduce, fields the event-type schema does
  not model); otherwise patch and re-run.
- `fail` (a load-bearing field missing or mismatched -- the detection
  would not fire) -> patch and re-run; never proceed on `fail`.

**Judge by the verdict; always show the human the diff.** The verdict
is the machine judgment; the human still needs to see what the
scenario actually emits against the captured event. As soon as a
draft reaches `pass` or `warn`, produce the structural diff of the
same render against its master (so it reflects the exact event behind
the verdict) and **show it verbatim in your visible reply inside a
fenced `diff` block** -- the human reads the actual diff in the
message, not a prose summary of it and not output left in a tool
result their client may collapse. A characterization ("environmental
churn only") may accompany the diff but never replaces it. If your
surface reports the diff as truncated, say so and point at the full
value differences in the comparison report. This lives in this step,
not in the report, so any caller that runs the fidelity step always
surfaces it (a `fail` is patched and re-run first; its diff appears on
the re-run that clears the fail).

The diff canonicalizes formatting (indentation, JSON key order, XML
quoting and empty-element form) and shows every remaining field
difference flat, unsuppressed. XML element and attribute order is not
canonicalized: `windows.wineventlog@v1` renders one line per event in
Windows schema order, exactly as a captured master, so an order
difference is a real one (for a new `UserData` provider element, add
its master order to the event type's `xml_envelope.order`).
Environmental fields (`gen.*` timestamps, GUIDs, request IDs, source
IPs) differ on every render by design -- that churn is expected, not a
defect, and on a `warn` it also helps you judge whether the
`missing_in_generated` entries are acceptable. The pass / warn / fail
signal remains the verdict, not the diff. If a *non-environmental*
field differs unexpectedly, that is a fidelity finding (patch the
draft and re-run Validate and Fidelity), not something to reconcile
from the diff. The diff shows only the first event of each side (the
master is one sample; a multi-emit render is a burst); byte-level
entity drift is out of its scope -- the comparison report's
`raw_encoding_drift` check owns that.

### 9. Job (optional)

Read `job-authoring.md` -- the job anatomy: the top-level `name`
(customer-facing Test name), workloads, state and bindings, pools,
loop/matrix, expectations, the `detection:` block.

- **With a detection profile**: the job targets the profile's `siem`,
  its content ID mirroring the scenario taxonomy. Workload
  expectations follow categorization: attack-positive and variants ->
  `expectation.expected: alert`, benign-control ->
  `expectation.expected: none` (a workload without an expectation
  validates vacuously). When the profile has a `threshold`, use the
  volumetric pattern: size `loop: N` so the burst satisfies the
  threshold predicate exactly as written (for `>` / `>=`, N above the
  threshold by a margin; for `<` / `<=` / `==`, N within the bound),
  binding the `group_by` tuple through job state (the Author scenarios
  bind rule) so the burst collapses into one group; the whole burst
  must land inside any `time_window`.
- **Without a profile**: author a generic orchestration job with no
  detection expectations claimed.

Whether or not a job was authored, now confirm the output destination
with the user and place the finished content there. If a job was
authored, validate it there, where its scenario references resolve.

### 10. Follow established patterns

Analyze established library patterns for jobs and job workloads and
make sure the content you author follows them:

- **state management**: a job keeps centralized state across workloads
  and drives workload state to make the output coherent, e.g., make
  actor, IP addresses, account ids, computer hostnames coordinated
  across workloads a job drives
- **idiomatic defaults**: refer to similar scenarios and jobs for
  established patterns in setting field defaults, e.g., account ids,
  actor names, IP addresses, computer hostnames, etc.

**Always** review the authored scenarios and jobs for adherence to
these patterns before submitting them.

### 11. Report

Each successfully-authored scenario (validated, fidelity `pass` or
accepted `warn`, or for a `kv` / `text` master a by-hand comparison)
already had its diff or comparison shown in the Fidelity step. The
report collects that evidence into one place; it does not re-run the
diff.

Close out with a report containing:

- the dataset summary (Summarize);
- the per-sample categorization table with slugs (Categorize);
- the detection profile, or an explicit statement that none was built
  and no rule-derived expectations are claimed;
- validation results for every draft and the job (Validate, Job);
- fidelity verdicts per scenario, with the justification for any
  accepted `warn` (Fidelity); for a `kv` / `text` master, the explicit
  statement that it has no verdict and the by-hand load-bearing
  comparison instead;
- the generated-vs-master diff for each successfully-authored scenario
  with a verdict (Fidelity);
- the job's content ID and SIEM targeting, when a job was authored;
- the output destination the user confirmed.

## Tagging taxonomy

Tags are an index over dimensions the content ID and `mitre:` block do
not already encode. Every tag must fit a closed dimension below; if
none applies, omit `tags:` entirely (most jobs end up here).

| Dimension | When | Values |
|---|---|---|
| Identifier | only when the content ID does not already encode it | `eid<N>` for Windows event logs -- the content ID uses semantic category names (`process-access`), so the numeric tag bridges to tag search (`eid10`). Skip when the slug IS the identifier (`delete-trail` already encodes `delete-trail`). |
| Threat | optional, multi | kebab-case campaign / actor / incident (`3cx`, `apt29`, `lockbit`) -- only when the entry mirrors a named campaign, not generic technique simulation. |
| Tool | optional, multi | kebab-case adversary tool (`procdump`, `mimikatz`) -- only when the entry emits artifacts unique to that tool (image path, distinctive command line). |
| CVE | optional, multi | `cve-YYYY-NNNNN`, lowercase prefix (`cve-2023-29059`) -- only when the entry exercises behavior tied to that assigned CVE. |

Examples and counter-examples:

| Entry | Tags | Why |
|---|---|---|
| `scenarios/windows/sysmon/dns-query/3cx-ioc-dns-query` | `[eid22, 3cx, cve-2023-29059]` | identifier + named campaign + assigned CVE |
| `scenarios/windows/sysmon/process-access/lsass-dump-procdump` | `[eid10, procdump]` | identifier + tool-unique artifacts |
| `scenarios/aws/cloudtrail/delete-trail` | omitted | content ID already encodes the slug; no threat/tool/CVE |
| `jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts` | omitted | typical job: no cross-cutting dimension |
| any | never `aws`, `iam`, `splunk`, `logon`, ... | provider / service / SIEM / category live in the content ID |
| any | never tactics, technique IDs, `attack`, `benign` | the `mitre:` block encodes them; its presence (attack) or absence (benign) is the role signal |
| any | never `auth`, `network`, `evasion`, ... | free-form hints collapse into MITRE vocabulary |
