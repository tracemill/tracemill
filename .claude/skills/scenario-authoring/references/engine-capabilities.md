# Engine capabilities for scenario authoring

Scenario `state:` and emit `fields:` are evaluated as expressions.
Prefer the engine's built-in `gen.*` generators and `fn.*` transforms
over hand-rolled literals so values look realistic across runs.

**Single source of truth.** The complete `gen.*`/`fn.*` catalog is
published at https://tracemill.io/docs/learn/expressions. Do NOT
invent names not listed there. If a generator or transform you want
does not exist (e.g. `fn.blake2()`), hardcode a plausible literal
instead. The table below is the commonly-used subset these surfaces
actually exercise (verified against the engine); consult the URL for
the full catalog. This reference otherwise documents authoring
*idioms* on top of the catalog.

| Name | Args | Purpose |
|---|---|---|
| `gen.timestamp` | `format=` (default RFC3339; `wineventlog`, `sysmon`) | Event timestamp in the surface's wire format. |
| `gen.aws_identity` | `type=`, `userName=`, `accountId=` | Full CloudTrail `userIdentity` object for the identity type. |
| `gen.hostname` | `class=`, `domain=` | Plausible hostname for the machine class. |
| `gen.int` | `min=`, `max=` | Random integer in an inclusive range. |
| `gen.hex` | `len=`, `case=` | Random hex string of `len` chars, `lower` or `upper`. |
| `gen.uuid` | none | Random UUID. |
| `gen.ipv4` | none | Random IPv4 address. |
| `gen.username` | none | Plausible username. |
| `gen.aws_region` | none | Random AWS region code. |
| `gen.aws_account_id` | none | Random 12-digit AWS account ID. |
| `fn.md5` | positional input | MD5 hex digest of the input. |
| `fn.sha256` | positional input | SHA-256 hex digest of the input. |
| `fn.lower` | positional input | Lowercase the input. |
| `fn.upper` | positional input | Uppercase the input. |

## Expression forms

| Form | Where | Use |
|---|---|---|
| `gen.<name>([k=v, ...])` | scenario `state:`, emit `fields:`, event-type `defaults:`, job `state:`, workload `bindings:` | Produce a fresh value (random or context-derived) per evaluation. |
| `fn.<name>(<input>[, k=v, ...])` | same scopes | Pure transform on a positional input. The input may be any expression form, including nested `fn.*` / `gen.*` calls (composition rule below). |
| `ref.<var>[.path]` | same scopes (scope-specific) | Read a resolved variable; `.path` walks into object results (e.g. `ref.actor.arn`, `ref.new_key.userName`). |
| `pool.<id>[.field]` | job `state:` and workload `bindings:` ONLY | Draw from a pool. Rejected at load time elsewhere -- surface to a scenario via a `bindings:` lift (see `references/job-authoring.md`). |
| `"...${ref.var}..."` | string-typed values everywhere | Interpolate a resolved scalar into a string. Only `${ref.*}` is supported -- `${gen.*}` / `${fn.*}` are NOT valid; precompute into a state var first. |

Named-param values may be a literal or `ref.*` ONLY (e.g.
`gen.aws_identity(type=IAMUser, userName=ref.user_name, accountId=ref.account_id)`)
-- see the composition rule below for the hazard.

## Core idioms

**Object-generator idiom.** Object-shaped generators
(`gen.aws_identity`, `gen.aws_access_key`) are stored in scenario state
once and pathed into via `ref.<var>.<field>` (`ref.actor.arn`,
`ref.new_key.accessKeyId`). Re-calling the generator per field would
produce a different identity each time and break in-event correlation.

**Correlation idiom (hashes).** When the same logical entity appears
across multiple emits, hash a stable state variable once and reference
the result:

```yaml
state:
  file_path:    "C:\\Users\\victim\\Downloads\\invoice.exe"
  file_md5:     fn.md5(ref.file_path)
  file_sha256:  fn.sha256(ref.file_path)
```

Then reference `ref.file_md5` / `ref.file_sha256` in every emit that
needs the hash. When there is no content to hash (Activity GUIDs,
request correlation IDs), use `gen.hex(len=N, case=lower|upper)`.

**Composition rule.** `fn.*` POSITIONAL inputs accept any expression
form, including nested calls -- `fn.lower(gen.username())` and
`fn.upper(fn.md5(ref.image))` are valid. NAMED parameters (`k=v` args
on `gen.*` and `fn.*`) accept ONLY a literal or `ref.*`.

**Warning:** an `fn.*` / `gen.*` value in a named parameter is NOT a
syntax error -- it silently passes through as the literal string:
`gen.aws_identity(userName=fn.lower(ref.x))` produces a userName of
literally `fn.lower(ref.x)`. Nothing flags it; the broken value just
lands in the event.

Recommended style: promote intermediates to state variables -- it keeps
expressions readable, and it is the only correct way to feed a computed
value into a named parameter:

```yaml
state:
  domain_short:       CORP
  domain_short_lower: fn.lower(ref.domain_short)         # transform first
  domain_fqdn:        "${ref.domain_short_lower}.${ref.domain_tld}"
```

**String interpolation.** String values may embed `${ref.<var>}` /
`${ref.<var>.<path>}`. Only `${ref.*}` is supported -- `${gen.uuid()}`,
`${fn.upper(...)}`, and bare `${var}` are rejected by the parser.
Precompute into state, then interpolate the `ref` form:

```yaml
state:
  account_id:  "000000000000"
  aws_region:  us-east-1
  trail_name:  gen.username()
  # interpolate refs into a composed ARN literal:
  trail_arn:   "arn:aws:cloudtrail:${ref.aws_region}:${ref.account_id}:trail/${ref.trail_name}"
  bucket_arn:  "arn:aws:s3:::${ref.bucket_name}"
  # backslashes escape per YAML's double-quoted rules:
  source_image: "C:\\Users\\${ref.user}\\Tools\\procdump64.exe"
```

The interpolated value is the resolved scalar -- for object refs, path
in with dot-syntax (`${ref.actor.arn}`).

## Per-surface idioms

Pick the right `gen.timestamp` format and `gen.hostname` class for the
surface -- a wrong format silently breaks downstream parsing or
SIEM-side timestamp extraction.

### AWS CloudTrail (`scenarios/aws/<service>/...`)

Rules:

- Timestamps use `gen.timestamp()` with the default RFC3339 format --
  never `format=wineventlog` / `format=sysmon` (Windows-only).
- `userIdentity:` MUST come from `gen.aws_identity()` stored in state,
  not hand-built field-by-field -- the generator produces the right
  `principalId`/`arn`/`accessKeyId`/`sessionContext` shape per identity
  type, including the `webIdFederationData` placeholder validators
  expect on `AssumedRole`.
- Pin `aws_region` / `account_id` as literals in scenario state so emit
  fields and ARN interpolations stay correlated; use `gen.aws_region()`
  / `gen.aws_account_id()` only when the scenario needs cross-region or
  cross-account variation.
- `eventSource` determines the service path: the taxonomy directory is
  the API's owner (`eventSource` minus `.amazonaws.com`), not the
  delivery channel. The `aws/cloudtrail` path is reserved for
  CloudTrail's own management events (`DeleteTrail`, `StopLogging`).
- `userAgent` follows the corpus convention: an aws-cli-style UA string
  with the ` tracemill/1.0` watermark appended -- copy the shape from
  the exemplar and adjust the `md/command#...` segment to the modeled
  API; do not invent a new UA format.

Exemplar (landed, CI-validated):
`scenarios/aws/kms/put-key-policy-wildcard-encrypt.yaml` -- full
framework-field set (fields the logging pipeline stamps on every event
regardless of the API call: `eventVersion`, `eventCategory`,
`managementEvent`, `readOnly`, `resources[]`, `tlsDetails`), state-held
identity, ARN interpolation, and a multi-line policy document.

### Windows WinEventLog, Security audit (`scenarios/windows/wineventlog/...`)

Rules:

- `gen.timestamp(format=wineventlog)` is mandatory for
  `System.TimeCreated.@SystemTime` -- ISO8601 with 7-digit fractional
  seconds; Splunk's `XmlWinEventLog` sourcetype keys off that
  precision.
- `gen.hostname(class=windows-workstation)` for endpoint events,
  `class=windows-server` for DC/server roles; pass
  `domain=ref.domain_fqdn` for internal consistency with AD-shaped
  fields.
- Compose AD-shaped strings (DN, UPN, SID) via interpolation, e.g.
  `domain_dn: "DC=${ref.domain_short_lower},DC=${ref.domain_tld}"`.

Exemplar (landed, CI-validated):
`scenarios/windows/wineventlog/account-management/new-local-admin.yaml`
-- a correlated 4720 + 4732 pair with the full `System:` envelope,
domain/FQDN state block, composed user DN and SID, and a `wait:` step
between emits.

### Windows Sysmon (`scenarios/windows/sysmon/...`)

Rules:

- Sysmon emits two timestamps in two formats: outer
  `System.TimeCreated.@SystemTime` is `format=wineventlog`, inner
  `EventData` `UtcTime` is `format=sysmon`. Do not collapse them.
- Wrap `ProcessGUID`-shaped UUIDs in literal braces via interpolation;
  Sysmon's wire format carries the braces.
- Pick plausible `gen.int` ranges -- source PIDs `1000-9999`, system
  PIDs `1000-4000`, EventRecordID `5000-99999` -- not the default
  `0-1000000`.
- The event-category path segment encodes the EventID: `dns-query` = 22,
  `process-access` = 10, `process-create` = 1, `registry` = 12/13/14.
  Tag the scenario `eid<N>` (see the skill's tagging taxonomy).

Two-timestamp + braced-GUID pattern:

```yaml
state:
  source_guid_raw:     gen.uuid()
  source_process_guid: "{${ref.source_guid_raw}}"   # Sysmon wraps GUIDs in braces
steps:
  - emit:
      event_type: windows.wineventlog@v1    # Sysmon ships through the WinEventLog wrapper
      fields:
        System:
          TimeCreated:
            "@SystemTime": gen.timestamp(format=wineventlog)
        EventData:
          Data:
            - "@Name": UtcTime
              "#text": gen.timestamp(format=sysmon)   # Sysmon's own format
```

Exemplar (landed, CI-validated):
`scenarios/windows/sysmon/process-access/lsass-dump-procdump.yaml` --
EID 10 with both timestamps, braced source/target ProcessGUIDs,
realistic PID ranges, and a CallTrace composed via interpolation.

### Microsoft 365 / O365 Management Activity (`scenarios/o365/<workload>/...`)

Rules:

- The event type `o365.management@v1` auto-stamps `CreationTime`
  (its `timestamp:` field) on every emit, in O365's offset-less UTC
  format (`2006-01-02T15:04:05`). Do NOT set `CreationTime` in the
  scenario -- the runner overwrites it, and a hardcoded value would be
  ignored.
- The taxonomy `service` segment is the `Workload` (the Microsoft 365
  service the activity belongs to), kebab-cased:
  `o365/azure-active-directory/`, `o365/exchange/`, `o365/sharepoint/`,
  `o365/onedrive/`, `o365/microsoft-teams/`. This is the cloud
  `{provider}/{service}` taxonomy, with Workload as the service.
- Hardcode the load-bearing trio in scenario `state:` or emit `fields:`:
  `Operation` (the action the detection keys on -- emit it verbatim,
  including Entra ID English-sentence operations with trailing periods
  like `"Disable Strong Authentication."` and Exchange/Compliance
  PowerShell cmdlet names like `Set-Mailbox`), `Workload`, and
  `RecordType` (the numeric enum -- e.g. 15 for Entra ID logons, 8 for
  Entra ID admin/Graph, 1/2 for Exchange).
- `Id` is the per-record GUID and the event type's `correlation` field;
  use `gen.uuid()`. `OrganizationId` (tenant GUID) is a placeholder
  anchor pinned once in state so it stays constant across a burst
  (`"11111111-1111-1111-1111-111111111111"`). `ClientIP` uses
  `gen.ipv4()`. `UserId` is a UPN composed from a placeholder tenant
  (`user@example.onmicrosoft.com`).
- Integer-typed fields (`RecordType`, `UserType`, `Version`,
  `AzureActiveDirectoryEventType`) must be YAML integers, not quoted
  strings -- the schema enforces `type: integer`.
- Workload-specific extension blocks (`ExtendedProperties`,
  `ModifiedProperties`, `Actor[]`, `Target[]`, `DeviceProperties[]`,
  Exchange `Parameters[]`, SharePoint `ListId`/`Site`) are name/value
  arrays or nested objects; reproduce only what the detection or
  fidelity requires.

Timestamp: O365 has its own format on the wire. Do not use
`gen.timestamp(format=wineventlog|sysmon)` (Windows-only) or RFC3339
(appends a `Z`). `CreationTime` is auto-stamped by the event type; no
`gen.timestamp` call is needed in the scenario.

Exemplar (landed, CI-validated):
`scenarios/o365/azure-active-directory/user-logged-in.yaml` -- an Entra
ID `UserLoggedIn` (RecordType 15) with the common-core fields, a pinned
tenant anchor, `gen.uuid()` record Id, and the AAD `Actor`/`Target`/
`ExtendedProperties`/`DeviceProperties` extension arrays.

## Volumetric / threshold detections (`loop:` in the job, not `foreach` in the scenario)

Some detections fire on the *volume* of a repeated event --
`... | stats count ... by <fields> | where count > N`, distinct-count
thresholds. Two repetition primitives exist; pick by *why* you are
repeating:

- **Scenario `foreach`** iterates a `ref` to a list, emitting once per
  element. Use for **meaningful, distinct variants** (a list of
  identities, a set of source IPs) -- every pass is a *different* event
  shaped by its element.
- **Job workload `loop: N`** re-runs the whole scenario N times
  (job-only field). Use for pure *volume*: N occurrences whose only
  per-event variation is the `gen.*` fields each run re-evaluates
  (`eventID`, `eventTime`, `requestID`).

**Anti-pattern:** `foreach` over a throwaway integer list whose element
values are never read, just to manufacture volume. It bakes the burst
length into the scenario and makes it non-atomic. Pure volume is a
*job* property -- `loop: N`.

For a threshold detection: model the **single event** in the scenario
(one `emit`, no loop) and compose the burst in the **job** via
`loop: N`, pinning the detection's group-by tuple through job-state
`bindings:` so all N runs collapse into one group:

```yaml
# scenario: one denied call, no loop
state:
  account_id: "111122223333"
  aws_region: us-east-1
  source_ip:  gen.ipv4()
  user_name:  attacker
  actor:      gen.aws_identity(type=IAMUser, userName=ref.user_name, accountId=ref.account_id)
steps:
  - emit:
      event_type: aws.cloudtrail@v1
      fields:
        eventName:       ListFoundationModels
        errorCode:       AccessDenied
        awsRegion:       ref.aws_region
        sourceIPAddress: ref.source_ip
        userIdentity:    ref.actor
        # eventID / eventTime / requestID stay gen.* -> unique per loop iteration
```

```yaml
# job: loop the atom N>threshold times, binding the group-by fields from
# job state so every iteration shares one (src, user, ...) group
mitre:                          # attack jobs carry a top-level mitre: block
  tactics: [discovery]
  techniques: ["T1580"]

state:
  account_id: "111122223333"
  aws_region: us-east-1
  source_ip:  gen.ipv4()        # evaluated ONCE at job start -> constant across the burst
  user_name:  attacker
workloads:
  - scenario: scenarios/aws/bedrock/list-foundation-models-denied
    loop: 12                    # margin above the rule's `count > 9`
    bindings:
      account_id: ref.account_id
      aws_region: ref.aws_region
      source_ip:  ref.source_ip
      user_name:  ref.user_name
    expectation:
      summary: "Repeated denied ListFoundationModels enumeration from one identity"
      expected: alert
      mitre:
        tactics: [discovery]
        techniques: ["T1580"]
```

Rules:

- **Each `loop:` iteration re-evaluates scenario `state:`** -- fields
  NOT bound from job state get fresh `gen.*` values per iteration (what
  you want for `eventID` / `eventTime` / `requestID`).
- **Job state is evaluated once, at job start** -- `source_ip: gen.ipv4()`
  in job state is one value shared across all N iterations; that shared
  value collapses the burst into one `stats ... by` group.
- **Bind ONLY the fields the detection groups by.** A group-by field
  left as a per-scenario `gen.*` default varies per iteration, splits
  the burst, and the threshold never clears.
- **Do NOT bind a field the burst should vary** (e.g. `user_agent` when
  each scenario has its own command-specific value -- a job-level
  binding would override each scenario's correct default). One binding
  per group-by field, nothing more.
- **Pick `loop:` with margin above the threshold** (`count > 9` ->
  `loop: 12`, not the bare minimum `10`) to absorb dispatch-window
  edges.

Worked references (landed, CI-validated):

- `jobs/splunk/aws/bedrock/bedrock-model-enumeration-access-denied-burst.yaml`
  -- the pair above in full, across three enumeration APIs.
- `jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts.yaml`
  -- `loop: 50` plus an inline round-robin pool lifted through
  `bindings:` (one `pool.*` draw per iteration, fields pathed off the
  drawn row).

Fidelity note: a single-emit volumetric scenario renders exactly one
event, so its fidelity check (workflow step 10) uses only per-event
load-bearing tokens -- aggregate `dc(...)` tokens belong to job-level
validation.

## Library conventions

- **Placeholder anchors.** Reuse the corpus's environmental constants
  instead of inventing new ones: `aws_region: us-east-1`, `account_id`
  from the standard placeholders (`"000000000000"`, `"111111111111"`,
  `"111122223333"`); `CORP` / `local` for the Windows domain. For O365,
  pin the tenant GUID (`OrganizationId`) to
  `"11111111-1111-1111-1111-111111111111"` and compose user UPNs against
  `example.onmicrosoft.com`.
- **`tracemill/1.0` user-agent watermark.** CloudTrail `user_agent`
  values end with ` tracemill/1.0` appended to an otherwise-realistic
  UA string (see the CloudTrail rules above).
- **`mitre:` block.** Attack scenarios and jobs carry a top-level
  `mitre:` block (`tactics:` + `techniques:`); benign controls omit it.
  Its presence/absence is the attack-vs-benign role signal -- never
  duplicate tactics or technique IDs into `tags:`.
- **Job `expectation.summary`.** Each job workload carries a one-line
  human-readable `expectation.summary` of what it validates, alongside
  `expectation.expected`.

## Authoring checklist

Before promoting a draft, verify:

- The skill's Hard rules hold for every file (ASCII-only; standalone
  and vendor-agnostic content).
- Field-value sourcing follows workflow step 8: load-bearing values
  hardcoded in `state:` or wired through `ref.<var>` from `bindings:`
  (never a fresh `gen.*` inside the emit); environmental values
  (timestamps, GUIDs, request IDs, source IPs, PIDs) use `gen.*` --
  hardcoded literals in those positions are a smell.
- Library conventions above hold (placeholder anchors, UA watermark,
  `mitre:` block, `expectation.summary`).
- Named-parameter values are literal-or-`ref.*` only -- a nested
  `fn.*`/`gen.*` there silently passes through as a literal string
  (composition rule above). Nested calls in `fn.*` positional inputs
  are fine; prefer promoting intermediates to state for readability.
- Composed strings use `${ref.*}` interpolation, not YAML anchors or
  concatenation.
- `gen.aws_identity(...)` results stored once in state, pathed via
  `ref.<var>.<field>` -- never re-called per emit field.
- Timestamp `format=` matches the surface: RFC3339 default for
  CloudTrail, `wineventlog` for the `System.TimeCreated` envelope,
  `sysmon` for the inner Sysmon `UtcTime`.
- `gen.hostname` `class=` matches the workstation/server context.
- Volumetric / threshold detections model ONE event in the scenario and
  burst in the job via `loop: N` + group-by `bindings:` (section
  above).
- **Do not mirror a sibling scenario blindly.** Siblings are useful
  structurally, but their *field content* applies only to the API
  action they model. Re-verify every non-framework field -- and every
  CloudTrail framework field (`resources[]`, `eventCategory`,
  `sessionCredentialFromConsole`, `managementEvent`) -- against the
  target action's vendor documentation (the per-API reference page AND
  the service's CloudTrail logging page). Drop fields the docs don't
  justify.
