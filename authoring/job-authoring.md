# Job authoring

A job orchestrates one or more scenarios: it binds shared state into
them, repeats them (`loop:` / `matrix:`), draws variation from pools,
and attaches detection expectations. This guide covers job semantics
for the method's Job step. The Hard rules in `method.md` (ASCII-only;
standalone, vendor-agnostic content) apply to every job and pool file.

Your surface layer owns everything that depends on where the job lives
and how it is executed: the content-ID namespace, file placement, the
validation invocation, running the job, and how a Detection is bound
to the surface's detection catalog. Validating a job also validates
every scenario and pool it references.

## Exemplars (landed, CI-validated)

Read these instead of copying inline templates:

- `jobs/splunk/aws/kms/aws-kms-wildcard-encrypt-policy.yaml` --
  multi-workload job: shared job `state:` (including a
  `gen.aws_identity` actor and `gen.ipv4` source), per-workload
  `bindings:`, `expectation.expected: alert` with `summary`, top-level
  `mitre:` block.
- `jobs/splunk/o365/sharepoint/o365-exfiltration-via-file-access.yaml`
  -- inline CSV pool, a benign-control workload with `matrix:` over the
  pool and `expectation.expected: none`.
- `jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts.yaml`
  -- volumetric `loop: 50` burst with an inline round-robin pool lifted
  through `bindings:` (the one-draw-per-iteration idiom).

## Job anatomy

Top-level keys:

| Key | Purpose |
|---|---|
| `type` | Always `job`. |
| `name` | Customer-facing **Test name** describing the behavior exercised (required). Independent from `detection.name` -- it may echo the descriptive inner portion of an ESCU title but is its own field, never a database key, and must be normalized-unique across the public library. |
| `description` | What the job validates, in standalone prose (Hard rule 2). |
| `mitre` | Top-level `tactics:` + `techniques:` when the job exercises attack behavior; a benign-only job omits it. |
| `tags` | Per the tagging taxonomy in `method.md`; most jobs omit it. |
| `detection` | The optional single Detection the Test exercises. It is authored only at job level and applies to every expectation-bearing workload. See Detection. |
| `state` | Shared variables, evaluated ONCE at job start. |
| `pools` | Inline pool definitions and/or shared-pool attachments. |
| `workloads` | One entry per scenario execution (the only required list). |

Workload keys:

| Key | Purpose |
|---|---|
| `scenario` | Content ID of the scenario (`scenarios/<taxonomy-path>/<slug>`, no file extension). Your surface layer sets the namespace and any other accepted reference forms. |
| `loop` | Run the scenario N times (0/1 = once). Mutually exclusive with `matrix`. |
| `matrix` | Named axes; the scenario runs once per cartesian-product combination. Each axis is an inline scalar list or a `pool.<id>` reference (which enumerates every row exactly once, ignoring the pool's sampling mode). |
| `bindings` | Map of scenario state variable -> expression; overrides that variable's scenario-side declaration. |
| `expectation` | Detection expectation (below). A workload without one validates vacuously. |
| `concurrency`, `start_after`, `eps`, `output`, `fields` | Orchestration knobs (parallelism, delayed start, rate limit, per-workload output, static field injection) -- mostly for generic orchestration jobs. |

### Evaluation semantics

These three rules carry the whole design; get them right:

1. **Job `state:` is evaluated once, at job start.** A `gen.*` there
   produces one value shared by every workload and every iteration.
2. **Workload `bindings:` are re-evaluated per iteration** (each
   `loop:` pass, each `matrix:` combination). A binding value may be a
   literal, `ref.<job-state-var>`, a `gen.*`/`fn.*` call, a
   `pool.<id>[.field]` draw, or a `"${ref...}"` interpolation.
3. **Scenario `state:` is re-evaluated per iteration.** Bound names
   take the binding's value; unbound names keep their scenario-side
   defaults, so unbound `gen.*` fields are fresh every iteration.

Only explicit bindings flow into the scenario -- job state is visible
to binding expressions via `ref.*` but is never inherited implicitly.
`pool.*` is legal only in job `state:` and `bindings:` (see the
expression-forms table in `engine-capabilities.md`).

**Pool draw idiom.** To keep a drawn row's fields coherent, bind the
row once and path the fields off it -- per-field `pool.*` bindings each
draw independently and scramble values across rows:

```yaml
bindings:
  auth_row:    pool.ntlm-failure-modes      # one draw per iteration
  logon_type:  ref.auth_row.logon_type      # fields pathed off the row
  auth_pkg:    ref.auth_row.auth_package
```

(`detect-password-spray-attempts.yaml` above shows this in full.)

### Expectations

Verified field shape:

- `expected:` -- `alert` (the detection should fire) or `none` (it must
  not). Map straight from the method's Categorize labels: attack-positive and
  variants -> `alert`, benign-control -> `none`.
- `summary:` -- one human-readable line describing what this workload
  validates (library convention; always include it).
- `mitre:` -- optional per-expectation `tactics:` + `techniques:`,
  supplementing the job-level block. Landed jobs use either top-level
  only (the KMS exemplar) or per-expectation; omit on `none` (its absence is the benign signal).

### Detection

The optional Detection a Test exercises is recorded as one top-level
`detection:` block -- **provenance, not configuration** (authoring records which
Detection, it does not install it). When present, it applies to every workload
that has an `expectation:`. Do not author `expectation.detection`; a Test never
selects different Detections per workload.

Both `expected: alert` and `expected: none` remain valid without an authored
Detection. They produce Test outcomes without Detection attribution.

Block shape:

| Field | Required | Purpose |
|---|---|---|
| `source` | yes | `escu` (catalog-backed; the SIEM already operates it, enabled by name) or `custom` (SPL carried inline). |
| `name` | yes | The detection's **native saved-search title**. For `escu`, the exact installed title in `ESCU - <name> - Rule` form (not the bare security_content name); the catalog join is on `id`, so the title text is provenance/display only. |
| `id` | iff `escu` | Catalog id (security_content UUID) -- the durable join key, stable across renames. |
| `spl` | iff `custom` | The detection SPL, when no catalog entry backs it. |

`escu` and `custom` are mutually exclusive on the unused field: an `escu` block
must not carry `spl`, a `custom` block must not carry `id`.

The job's top-level `name` (the Test name) and `detection.name` are independent
even when their text overlaps -- e.g. a Test named `AWS IAM Delete Policy`
exercising detection `ESCU - AWS IAM Delete Policy - Rule`.

From a detection profile (the method's Profile step): emit `source: escu` with `name` +
`id` when the rule comes from a catalog entry with a stable id; otherwise
`source: custom` with `name` + the rule `spl`. A job without a Detection profile
omits `detection:`.

### Pools

A pool is a reusable value source (`csv`, `string_list`, `ip_range`)
with a `sampling.mode` (e.g. `round_robin`). Embed CSV rows under
`csv.data`; do not author `csv.path` or companion CSV files.

Two ways to use a pool:

- **Inline**, under the job's `pools:` with `id:`, `sampling:`, and the
  data (`csv.data: |` block or `string_list.values:`) --
  see the O365 file-access and password-spray exemplars.
- **Shared pool** (`type: pool`, its own file; your surface layer sets
  where it lives), for data worth reusing across jobs -- see
  `pools/windows-auth-profiles` (inline CSV) and
  `pools/single-letter-exe-names` (string list). A job attaches one by
  content ID:

  ```yaml
  pools:
    - id: auth-profiles            # local handle: pool.auth-profiles.<column>
      path: pools/windows-auth-profiles
  ```

  Here, `path` is the shared pool's content ID, not a `csv.path`
  filesystem source.

  The `id:` in the job entry is the handle `pool.<id>` references use.

## SIEM targeting

**With a detection profile** (the method's Profile step): the job is
written for the profile's `siem` -- which the user has already
confirmed -- and its content ID sits under that SIEM's job namespace,
mirroring the scenario taxonomy (endpoint:
`<platform>/<log-source>/<event-category>`; cloud:
`<provider>/<service>`, with a `multi-service` segment for workloads
spanning services with no single semantic owner). Your surface layer
gives the exact namespace.

The content ID is a contract -- renaming later is a breaking change.
Pick the `<job-slug>` from the behavior the job validates, kebab-case,
like scenario slugs.

**Without a profile** (no rule, or a rule in an unsupported /
SIEM-neutral form): author a generic orchestration job -- workloads,
state, bindings, pools, repetition, but no rule-derived expectations
claimed. It claims no SIEM job namespace; your surface layer says
where such a job lives.

## Volumetric jobs (profile has `group_by` + `threshold`)

The scenario models ONE event (the method's Author scenarios step); the
job supplies the volume:

- `loop: N` on the workload, with N above the threshold by a margin
  (`engine-capabilities.md`'s volumetric section gives the rule and a
  worked example).
- Bind exactly the profile's `group_by` tuple through job `state:` so
  all N iterations collapse into one aggregation group -- this is the
  Author scenarios bind rule (`method.md`) meeting evaluation rule 1
  above.

The full mechanics -- which fields to bind, which to leave varying, the
worked scenario/job pair -- live in the "Volumetric / threshold
detections" section of `engine-capabilities.md`; follow that
section rather than improvising. When the rule wants distinct values
across the burst (a distinct-count threshold), draw them from a pool
via `bindings:` or expand them with `matrix:` instead of leaving them
to chance.

## What authoring does NOT produce

- **`expectation.correlation`.** Some landed jobs carry a
  `correlation:` map inside expectations, tying job-state values to
  fields of the fired alert. Writing one requires firing the rule on a
  live SIEM and inspecting the alert it produces -- out of authoring
  scope. Leave `correlation:` absent; `expected:` + `summary:` are a
  complete expectation.
- **SIEM rule / savedsearch installation or configuration.** Authoring
  assumes no SIEM config-plane access. The job validates against a
  detection the user already operates.
