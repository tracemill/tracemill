# Job authoring

A job orchestrates one or more scenarios: it binds shared state into
them, repeats them (`loop:` / `matrix:`), draws variation from pools,
and attaches detection expectations. This reference covers the generic
job shape (workflow step 11) and where the finished job lands. The
skill's Hard rules (ASCII-only; standalone, vendor-agnostic content)
apply to every job and pool file.

Validate a draft with:

```bash
tracemill validate --job <draft-path>
```

which also validates every referenced scenario and pool. Add
`--library <path-to-checkout>` when authoring against a checkout.

## Exemplars (landed, CI-validated)

Read these instead of copying inline templates:

- `jobs/splunk/aws/kms/aws-kms-wildcard-encrypt-policy.yaml` --
  multi-workload job: shared job `state:` (including a
  `gen.aws_identity` actor and `gen.ipv4` source), per-workload
  `bindings:`, `expectation.expected: alert` with `summary`, top-level
  `mitre:` block.
- `jobs/splunk/windows/sysmon/process-access/access-lsass-memory-for-dump.yaml`
  -- inline CSV pool, a benign-control workload with `matrix:` over the
  pool and `expectation.expected: none`, attack workloads with
  per-expectation `mitre:` blocks.
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
| `tags` | Per the skill's tagging taxonomy; most jobs omit it. |
| `detection` | The detection a Splunk job validates (job-level default, applied to every workload). See Detection. CI requires every workload of a `jobs/splunk/**` job to resolve to a detection. |
| `state` | Shared variables, evaluated ONCE at job start. |
| `pools` | Inline pool definitions and/or shared-pool attachments. |
| `workloads` | One entry per scenario execution (the only required list). |

Workload keys:

| Key | Purpose |
|---|---|
| `scenario` | Content ID (`scenarios/<taxonomy-path>/<slug>` -- no `library/` prefix, no `.yaml`). Values starting with `./`, `/`, or `~` are file paths instead -- useful for project-local drafts. |
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
expression-forms table in `references/engine-capabilities.md`).

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
  not). Map straight from step-6 categorization: attack-positive and
  variants -> `alert`, benign-control -> `none`.
- `summary:` -- one human-readable line describing what this workload
  validates (library convention; always include it).
- `mitre:` -- optional per-expectation `tactics:` + `techniques:`,
  supplementing the job-level block. Landed jobs use either top-level
  only (the KMS exemplar) or per-expectation (the lsass exemplar);
  omit on `none` (its absence is the benign signal).
- `detection:` -- the detection this specific workload validates; see
  Detection below. Optional here when a job-level `detection:` already
  supplies the default (the common case).

### Detection

The detection a Splunk job validates is recorded as a `detection:` block --
**provenance, not configuration** (the skill records which detection, it does
not install it). Place it either:

- **Job-level** (top-level `detection:`) -- the default, applied to every
  workload that has an `expectation:`. Use this for the common case where all
  workloads (attack variants + benign controls) validate the same detection.
- **Per-workload** (`expectation.detection`) -- overrides the job-level default
  for that workload, for a job that validates different detections across
  workloads (e.g. a multi-stage campaign).

Resolution per workload: `expectation.detection` if present, else the job-level
`detection`. Every workload that has an `expectation:` (both `alert` and `none`
-- a `none` control asserts a *specific* detection stays silent) must resolve to
one; observation-only workloads (no expectation) need none.

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

From a detection profile (workflow step 5): emit `source: escu` with `name` +
`id` when the rule comes from a catalog entry with a stable id; otherwise
`source: custom` with `name` + the rule `spl`. A generic orchestration job (no
profile, not under `jobs/splunk/**`) omits `detection:`.

### Pools

A pool is a reusable value source (`csv`, `string_list`, `ip_range`)
with a `sampling.mode` (e.g. `round_robin`). Two ways to use one:

- **Inline**, under the job's `pools:` with `id:`, `sampling:`, and the
  data (`csv.data: |` block, `csv.path:`, or `string_list.values:`) --
  see the lsass-dump and password-spray exemplars.
- **Shared pool YAML** at `pools/<pool-name>.yaml` (`type: pool`), for
  data worth reusing across jobs -- see `pools/windows-auth-profiles.yaml`
  (CSV-backed) and `pools/single-letter-exe-names.yaml` (string list).
  A job attaches one by content ID:

  ```yaml
  pools:
    - id: auth-profiles            # local handle: pool.auth-profiles.<column>
      path: pools/windows-auth-profiles
  ```

  The `id:` in the job entry is the handle `pool.<id>` references use.

## SIEM placement

**With a detection profile** (workflow step 5): the job is written for
the profile's `siem` -- which the user has already confirmed -- and
lands in the library jobs tree under that SIEM root, mirroring the
scenario taxonomy (library README, "Directory Taxonomy"):

- Endpoint: `jobs/<siem>/<platform>/<log-source>/<event-category>/<job-slug>.yaml`
- Cloud: `jobs/<siem>/<provider>/<service>/<job-slug>.yaml`; workloads
  spanning services with no single semantic owner go under
  `jobs/<siem>/<provider>/multi-service/`.

The path is the job's content ID, so it is a contract -- renaming later
is a breaking change. Keep the `jobs/<siem>/...` path relative to
whatever content root the user chose (project-local directory or
library checkout): the taxonomy is the content-ID contract and must be
preserved so the job stays contribution-ready. Pick the `<job-slug>`
from the behavior the job validates, kebab-case, like scenario slugs.

**Without a profile** (no rule, or a rule in an unsupported /
SIEM-neutral form): author a generic orchestration job -- workloads,
state, bindings, pools, repetition, but no rule-derived expectations
claimed. It stays project-local (the default output destination in the
skill's "Working directories" section, e.g. `./jobs/<job-slug>.yaml`)
and claims no `jobs/<siem>/...` library namespace.

## Volumetric jobs (profile has `group_by` + `threshold`)

The scenario models ONE event (workflow step 8); the job supplies the
volume:

- `loop: N` on the workload, with N above the threshold by a margin
  (engine-capabilities.md's volumetric section gives the rule and a
  worked example).
- Bind exactly the profile's `group_by` tuple through job `state:` so
  all N iterations collapse into one aggregation group -- this is the
  step-8 bind rule (SKILL.md) meeting evaluation rule 1 above.

The full mechanics -- which fields to bind, which to leave varying, the
worked scenario/job pair -- live in the "Volumetric / threshold
detections" section of `references/engine-capabilities.md`; follow that
section rather than improvising. When the rule wants distinct values
across the burst (a distinct-count threshold), draw them from a pool
via `bindings:` or expand them with `matrix:` instead of leaving them
to chance.

## What this skill does NOT author

- **`expectation.correlation`.** Some landed jobs carry a
  `correlation:` map inside expectations, tying job-state values to
  fields of the fired alert. Writing one requires firing the rule on a
  live SIEM and inspecting the alert it produces -- out of this skill's
  scope. Leave `correlation:` absent; `expected:` + `summary:` are a
  complete expectation.
- **SIEM rule / savedsearch installation or configuration.** The skill
  assumes no SIEM config-plane access. The job validates against a
  detection the user already operates.

## Running the job

This skill authors and locally validates jobs (`tracemill validate
--job`); it does not run them against a live SIEM. Executing a job for
real detection validation needs platform access this skill does not
assume, so it is out of scope here.
