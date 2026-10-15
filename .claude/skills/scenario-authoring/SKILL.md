---
name: scenario-authoring
description: >-
  Use when authoring tracemill scenarios and validation jobs from a sample telemetry dataset (xml/json/ndjson/kv/text), optionally guided by a detection rule (v1 supported format: Splunk SPL). Produces schema-validated, fidelity-checked scenario and job YAML for supported event types (aws.cloudtrail@v1, windows.wineventlog@v1, o365.management@v1, azure.monitor.aad@v1, gcp.audit@v1, aws.asl@v1). Works entirely with the local tracemill CLI (0.11.7 or later); no account or network needed.
---

# scenario-authoring: dataset -> validated scenarios and jobs (CLI)

This skill is the command-line binding of the authoring method. The
method -- what each step decides, the rules, the profile contract, how
to read verdicts -- lives in the library's `authoring/` directory
(from this skill's directory: `../../../authoring/`):

- `authoring/method.md` -- **read it first**; the steps below follow
  its numbering and only add the concrete commands and the rules that
  belong to this surface.
- `authoring/engine-capabilities.md`, `authoring/job-authoring.md`,
  `authoring/detections/splunk-spl.md` -- read when a method step
  points at them.

Everything runs through the `tracemill` CLI. Run from the project root
so the working directory (`.cache/scenario-authoring/`) lands in the
project.

## Preflight

The `tracemill author` commands need CLI 0.11.7 or later. Check before
anything else:

```bash
MIN=0.11.7
v=$(tracemill version 2>/dev/null | awk '/^Version:/{print $2}'); v=${v#v}
if [ -z "$v" ]; then
  echo "tracemill not found: install $MIN or later"
elif printf '%s\n' "${v%%-*}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  base=${v%%-*}
  if [ "$(printf '%s\n' "$MIN" "$base" | sort -V | head -n1)" != "$MIN" ] \
     || { [ "$base" = "$MIN" ] && [ "$base" != "$v" ]; }; then
    echo "tracemill $v is older than $MIN: upgrade the CLI"
  else
    echo "ok: tracemill $v"
  fi
elif tracemill author --help >/dev/null 2>&1; then
  echo "warning: unversioned build '$v'; author commands present"
else
  echo "tracemill '$v' has no 'author' command: install $MIN or later"
fi
```

Anything but `ok` or the unversioned-build warning: stop and tell the
user to upgrade. Do not fall back to hand-rolled tooling.

`author` exit codes: `0` success (a fidelity `fail` or `warn` verdict
still exits `0` -- read the verdict from the report), `1` runtime
failure (missing input, failed download, a bound exceeded, no match,
no group-by tuple, no fidelity verdict, Splunk error), `2` invalid
invocation.

## CLI rules

In addition to the method's Hard rules:

- **Never read a dataset in full.** Datasets can be MB- to GB-scale;
  use bounded reads (`head`, `wc -l`) and `tracemill author extract`
  for all summarization and sample extraction. Do not hand-roll
  awk/sed/jq/yq pipelines over the raw dataset (targeted reads of
  extracted single-event samples are fine). If the dataset fits none
  of the supported formats, abort with the step-0 sniff output -- do
  not paper over with a one-off extractor.
- **ASCII check** (method Hard rule 1), per authored file; empty
  output = clean:

  ```bash
  LC_ALL=C grep -nP '[^\x00-\x7F]' <file>
  ```

## Working directory

```text
.cache/scenario-authoring/
  attack_data/              # step 0: downloaded datasets (CLI URL cache)
  samples/<dataset-slug>/   # step 2: one sample per category
  masters/                  # step 5: promoted master samples
  drafts/scenarios/         # step 6: scenario drafts
  drafts/jobs/              # step 9: job drafts
  generated/                # step 8: renders, fidelity reports
  gap-archive/<run-id>/      # retained unpublished gap drafts and evidence
```

Nothing outside it is written until the user confirms an output
destination (step 9). At the start of a fresh run, clear `samples/`,
`masters/`, `drafts/`, and `generated/` (keep `attack_data/`, which is
content-addressed) and `gap-archive/`. The gap archive is retained evidence;
other contents under `.cache/scenario-authoring/` are disposable.

`<dataset-slug>` is the dataset filename without its extension,
kebab-cased (for a URL, its basename).

## Steps

### 0. Acquire and sniff

A local file is used in place. A URL (`http://` or `https://`) is
downloaded by the first `tracemill author extract` call: run step 1
with `--format auto` on the URL, which caches it at
`.cache/scenario-authoring/attack_data/<sha256><ext>` (identical
content never duplicates) and prints `dataset: <path>` to stderr. Use
the printed path in every later step, starting with the sniff below;
if the sniff disagrees with the summary's `format`, re-run step 1 on
the cached path with the format you decided.

Sniff the format with three bounded commands on the local path:

```bash
file <path> && head -n 5 <path> && wc -l <path>
```

Decide: `xml` | `json` | `ndjson` | `kv` | `text`. Binary -> abort with
"convert to a text format and re-invoke". If the decision is
ambiguous, pass `--format auto`. For `text`, or `kv` whose surface
renders XML or JSON (anything but `windows.admon@v1`), tell the user
now that step 8 gives no fidelity verdict for it (see there).

### 1. Summarize

```bash
tracemill author extract <path-or-url> --format <fmt> --key <key> --mode summary
```

Prints `{format, total, key, categories: [{key, count}, ...]}` --
record it for the report. Keys are dotted paths for JSON / NDJSON,
slash paths for XML (`System/EventID`), field names for kv. A kv
dataset framed by timestamp lines (classic `WinEventLog` text, admon)
is grouped per record, and a body field is a dotted path in the
method's escaped form (`Message.Process Information.New Process Name`).

Bounds: `--max-bytes` (default 2 GiB; the dataset is held in memory),
`--max-events` (5,000,000), `--max-categories` (10,000). Exceeding one
exits `1` naming the flag; raise it only after confirming with the
user.

### 2. Sample

```bash
tracemill author extract <path> --format <fmt> --key <key> \
  --mode samples --out .cache/scenario-authoring/samples/<dataset-slug>/
```

Writes the first event of each category to its own file, with the
dataset format's extension (`.xml`, `.json`, `.ndjson`, ...); prints
`[{key, count, sample_path}, ...]`. Key characters outside
`A-Za-z0-9._-` are sanitized; collision-prone or long keys get a
checksum suffix. For one specific category:

```bash
tracemill author extract <path> --format <fmt> --key <key> \
  --mode extract --value <value> --out <file>
```

### 3. Profile (optional)

Static analysis per `authoring/detections/splunk-spl.md`. To
cross-check the group-by tuple (that module's section 4), parse the SPL
live through a Splunk management endpoint:

```bash
tracemill author spl-groupby '<spl>'
```

| Variable | Meaning |
|---|---|
| `SPLUNK_URL` | Management URL, e.g. `https://splunk.example.com:8089` (required for live mode) |
| `SPLUNK_AUTH` | `user:password` |
| `SPLUNK_PASSWORD` | used as `admin:$SPLUNK_PASSWORD` when `SPLUNK_AUTH` is unset |
| `SPLUNK_INSECURE` | `1` skips TLS verification (self-signed dev instance only) |

Or reduce a saved parser response (from a POST to
`/services/search/parser`) instead:

```bash
tracemill author spl-groupby --parser-json <file|->
```

Output: one field per line on stdout, warnings on stderr as
`warning: <text>`; `--output json` prints `{"fields": [...],
"warnings": [...]}`. Count-only or no-aggregation SPL exits `1` with a
named message. With `SPLUNK_URL` unset and no saved response, skip the
cross-check: static reading is the only path, which is fine.

### 4. Categorize

Read each sample bounded (`head -n 20`, targeted `jq` / `yq` paths on
the extracted sample file, never the dataset).

### 5. Promote masters

```bash
mkdir -p .cache/scenario-authoring/masters/
cp .cache/scenario-authoring/samples/<dataset-slug>/<sample-file> \
   .cache/scenario-authoring/masters/<slug>.<ext>
```

### 6. Author scenarios

Write drafts to
`.cache/scenario-authoring/drafts/scenarios/<taxonomy-path>/<slug>.yaml`
(taxonomy per the method; library README "Directory Taxonomy"). Run the
ASCII check on each.

### 7. Validate

```bash
tracemill validate --scenario <draft-path>
```

Add `--library <path-to-library-checkout>` when authoring against a
checkout; without a library the event-type payload check is skipped
with a warning.

### 8. Fidelity

`author fidelity` judges XML and JSON (NDJSON, `Records[]`) masters,
and a `kv` master against a `kv` render (`windows.admon@v1`). A `kv`
master against an XML or JSON render, or any `text` input, has no
verdict: the command exits `1` with `no fidelity verdict` and prints
no report and no diff. Then skip the commands below, render the
draft with `tracemill --library <checkout> run scenario <draft-path>`,
and follow the method's by-hand path, checking the load-bearing
fields in every rendered event.

Otherwise name the generated file with the master's extension, which
step 2 took from the dataset's format (`.xml`, `.json`, `.ndjson`, or
`.log` for kv). The render's format follows the surface (XML for
`windows.wineventlog@v1`, kv for `windows.admon@v1`, NDJSON for JSON
surfaces) and the comparison auto-detects each, so never pass
`--format` (`xml`, `json` and `kv` only force a format):

```bash
M=.cache/scenario-authoring/masters/<slug>.<ext>
G=.cache/scenario-authoring/generated
mkdir -p "$G"
tracemill --library <checkout> run scenario <draft-path> > "$G/<slug>.<ext>"
tracemill author fidelity --master "$M" --generated "$G/<slug>.<ext>" \
  --load-bearing '<tokens>' > "$G/<slug>.fidelity.json"
jq -r .verdict "$G/<slug>.fidelity.json"
```

`--load-bearing` takes the method's token grammar. Once the verdict is
`pass` or `warn`, produce the diff from the same render and paste it
verbatim in a fenced `diff` block, per the method:

```bash
tracemill author fidelity --master "$M" --generated "$G/<slug>.<ext>" --output diff
```

### 9. Job (optional)

Draft to `.cache/scenario-authoring/drafts/jobs/...`.

**Gap variants and controls.** Set expectations from the desired security
outcome: a missed attack expects `alert`; a false-positive probe expects
`none`. Never invert either to match a known defect. A variant outside the
current SPL's scope is not necessarily benign. When the platform repository
is available, cross-reference its `docs/detection-gaps/` notes with the
actual scenario bindings and current job; notes may describe stale or
unauthored variants. Keep gap demonstrations in separate jobs and report
their evidence separately from ordinary coverage and benign controls.
Use the dedicated gap corpus once its namespace is supported (check the
tracking issue and the checkout's documented job paths); until then,
keep new gap-job drafts in the cache and disclose that they are not
published. [Platform #2070](https://github.com/tracemill/platform/issues/2070)
tracks the proposed `jobs/splunk-gaps/...` layout. Do not invent schema
fields or treat `splunk-gaps` as a SIEM. This publication restriction applies
to shared-library contributions, not user-requested local research jobs.
For an unpublished gap draft, validate a temporary project-local copy using
the Default output destination below. Place only new scenario drafts in
that content root; resolve existing shared scenarios through `--library
<checkout>` without copying them. Before removing temporary files, archive
the job, new scenario drafts, fidelity and validation evidence, and shared
library revision under `.cache/scenario-authoring/gap-archive/<run-id>/`.
Cite that retained archive in the report. This validates the job without
publishing it to the shared library.

**Content-ID namespace and placement.** With a profile, the job's
content ID is its path under a `jobs/<siem>/` root, mirroring the
scenario taxonomy (library README, "Directory Taxonomy"):

- Endpoint: `jobs/<siem>/<platform>/<log-source>/<event-category>/<job-slug>.yaml`
- Cloud: `jobs/<siem>/<provider>/<service>/<job-slug>.yaml`; workloads
  spanning services with no single semantic owner go under
  `jobs/<siem>/<provider>/multi-service/`.

Keep the `jobs/<siem>/...` path relative to whichever content root the
user chooses (project-local directory or library checkout), so the job
stays contribution-ready. Without a profile, the job is project-local
(e.g. `./jobs/<job-slug>.yaml`) and claims no `jobs/<siem>/` namespace.
A workload's `scenario:` may also be a file path (starting with `./`,
`/`, or `~`) -- useful for project-local drafts. A new shared pool goes
at `pools/<pool-name>.yaml`.

**Detection binding.** The job's `detection:` block (see
`authoring/job-authoring.md`) is the catalog binding on this surface:
`source: escu` + `id` for a security_content detection, otherwise
`source: custom` + `spl`.

**Move, then validate.** Confirm the output destination with the user
and move the finished drafts out of `.cache/` (see "Output
destination"). Validate the job only after the move: its content-ID
scenario references resolve from the destination content root, not
from `.cache/` (validating there fails with "content not found"). From
the destination root:

```bash
tracemill --library <checkout> validate --job <dest-job-path>
```

**Running the job** against a live SIEM is out of scope: this skill
authors and locally validates content; executing a job for detection
validation needs platform access it does not assume.

### 10-11. Patterns and report

As in the method. In the report, cite the fidelity JSON paths under
`.cache/scenario-authoring/generated/` as the evidence files.

## Output destination

Once the destination is confirmed (step 9), move drafts out of
`.cache/` to one of:

- **Default -- project-local content**: copy finished files into the
  project's own content tree (e.g. `./scenarios/...`, `./jobs/...`)
  and run them by file path or through the CLI's content layering
  (project content takes precedence over user content, which takes
  precedence over the installed library).
- **Alternative -- contribute to a library checkout**: place files per
  the library taxonomy (library README), run `tracemill validate --dir
  .` from the checkout root, and open a PR.
