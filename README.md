# Tracemill Content Library

Open source scenarios, jobs, and event types for validating detective controls end-to-end with [Tracemill](https://tracemill.io).

This library is distributed to end users via `tracemill update` and installed to `~/.tracemill/library/`. Users should not edit the installed copy directly — the entire directory is replaced on each update.

## Quick Start

Install the CLI with Homebrew, or download a binary from the [installation guide](https://tracemill.io/docs/installation):

```bash
brew install tracemill/tap/tracemill
```

Fetch the latest content library into `~/.tracemill/library/`:

```bash
tracemill update
```

Run your first scenario by content ID. With no destination flags, Tracemill writes JSONL to stdout:

```bash
tracemill run scenarios/aws/cloudtrail/delete-trail
```

Preview the same scenario without emitting events:

```bash
tracemill run scenarios/aws/cloudtrail/delete-trail --dry-run
```

Run a job. Jobs orchestrate one or more scenarios and can bind shared pools, loops, matrices, and detection expectations:

```bash
tracemill run jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts
```

Override job state at invocation time with repeatable `--set key=value` flags. The key must already exist in the job's `state:` block:

```bash
tracemill run jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts \
  --set src_host=10.10.20.30 \
  --set host=WS-FINANCE-042
```

Send events to Splunk HEC. When `--hec-url` is set, the CLI auto-infers `--target-type splunk` so generated Windows XML matches Splunk ingestion behavior:

```bash
tracemill run jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts \
  --hec-url https://splunk.example.com:8088 \
  --hec-token your-hec-token
```

Other destinations are available too:

```bash
# S3 in CloudTrail layout
tracemill run scenarios/aws/cloudtrail/delete-trail \
  --s3-bucket cloudtrail-test-events \
  --s3-region us-east-1 \
  --s3-format cloudtrail

```

This is a focused subset of the CLI docs. For every command, flag, destination, environment variable, and content resolution rule, see the [CLI reference](https://tracemill.io/docs/reference/cli).

## What's Included

The library currently includes ready-to-run AWS CloudTrail scenarios, Windows Sysmon scenarios, Windows Event Log scenarios, Microsoft 365 / O365 Management Activity scenarios, Microsoft Entra ID (Azure AD) Monitor sign-in log scenarios, Splunk detection validation jobs, reusable pools, and event-type schemas.

```bash
# Browse installed content after `tracemill update`
find ~/.tracemill/library/scenarios -name '*.yaml'
find ~/.tracemill/library/jobs -name '*.yaml'

# Inspect schemas known to the engine
tracemill list event-types

# Validate local content before opening a PR
tracemill validate --dir .
```

## Content Types

**Scenarios** are atomic and self-contained. A scenario is a single YAML file with no external dependencies — it uses generators, refs, and state, all defined inline.

**Jobs** wire scenarios together with pools, bindings, and concurrency settings. Jobs reference scenarios and shared pools by content ID.

**Pools** are reusable data sources (IP ranges, string lists, CSV references) that jobs bind to scenarios at runtime.

**Event types** declare the schema and engine metadata for a class of generated events. Scenarios reference event types by `id@version` (e.g. `aws.cloudtrail@v1`); the engine validates every emitted event against the declared JSON Schema.

## Repository Structure

Content is organized by type at the top level, then by provider and service, e.g.:
```
scenarios/
  aws/
    cloudtrail/
      delete-trail.yaml                     # type: scenario
    iam/
      create-access-key.yaml                # type: scenario
      discovery-access-denied-burst.yaml    # type: scenario
      update-login-profile.yaml             # type: scenario
    s3/
      put-bucket-lifecycle.yaml             # type: scenario
  gcp/
    cloudfunctions/
      deploy-function-impersonate-sa.yaml   # type: scenario
  o365/
    azure-active-directory/
      advanced-audit-disabled.yaml          # type: scenario
  windows/
    sysmon/
      process-access/
        lsass-dump-procdump.yaml            # type: scenario
        lsass-dump-comsvcs.yaml             # type: scenario
        lsass-access-routine.yaml           # type: scenario
    wineventlog/
      account-management/
        new-local-admin.yaml                # type: scenario
        user-account-created.yaml           # type: scenario
        local-group-member-added.yaml       # type: scenario
event-types/
  aws/
    cloudtrail/
      v1.yaml                              # type: event-type
  azure/
    monitor-aad/
      v1.yaml                              # type: event-type
  gcp/
    audit/
      v1.yaml                              # type: event-type
  o365/
    management/
      v1.yaml                              # type: event-type
pools/
  single-letter-exe-names.yaml             # type: pool
jobs/
  splunk/
    aws/
      iam/
        aws-iam-accessdenied-discovery-events.yaml  # type: job
      multi-service/
        aws-defense-evasion-impair-security-services.yaml  # type: job
    o365/
      azure-active-directory/
        o365-advanced-audit-disabled.yaml        # type: job
    windows/
      wineventlog/
        logon/
          detect-password-spray-attempts.yaml   # type: job
```

The `type:` field in each YAML file identifies what it is. The tree structure provides organization, not type disambiguation.

## Content IDs

Every file has a content ID: its path from the repository root, minus the `.yaml` extension. Content IDs are how users and jobs reference content.

| File | Content ID |
|---|---|
| `scenarios/aws/cloudtrail/delete-trail.yaml` | `scenarios/aws/cloudtrail/delete-trail` |
| `scenarios/aws/iam/create-access-key.yaml` | `scenarios/aws/iam/create-access-key` |
| `scenarios/aws/s3/put-bucket-lifecycle.yaml` | `scenarios/aws/s3/put-bucket-lifecycle` |
| `scenarios/o365/azure-active-directory/advanced-audit-disabled.yaml` | `scenarios/o365/azure-active-directory/advanced-audit-disabled` |
| `scenarios/windows/sysmon/dns-query/3cx-ioc-dns-query.yaml` | `scenarios/windows/sysmon/dns-query/3cx-ioc-dns-query` |
| `scenarios/windows/sysmon/process-access/lsass-dump-procdump.yaml` | `scenarios/windows/sysmon/process-access/lsass-dump-procdump` |
| `scenarios/windows/wineventlog/account-management/new-local-admin.yaml` | `scenarios/windows/wineventlog/account-management/new-local-admin` |
| `jobs/splunk/o365/azure-active-directory/o365-advanced-audit-disabled.yaml` | `jobs/splunk/o365/azure-active-directory/o365-advanced-audit-disabled` |
| `jobs/splunk/windows/sysmon/process-access/access-lsass-memory-for-dump.yaml` | `jobs/splunk/windows/sysmon/process-access/access-lsass-memory-for-dump` |
| `jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts.yaml` | `jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts` |

Content IDs are stable identifiers. Users reference them in jobs, scripts, and CI pipelines. Renaming or moving a file is a breaking change.

## Directory Taxonomy

The directory path is part of the content ID, so the taxonomy is a contract. Follow these conventions:

- Cloud scenarios: `scenarios/{provider}/{service}/{scenario-name}` — e.g., `scenarios/aws/iam/create-access-key`
- Endpoint scenarios: `scenarios/{platform}/{log-source}/{event-category}/{scenario-name}` — e.g., `scenarios/windows/sysmon/process-access/lsass-dump-procdump`
- Network scenarios: `scenarios/{protocol-or-domain}/{scenario-name}` — e.g., `scenarios/dns/tunneling`
- Jobs: `jobs/{siem}/{vendor}/{product}/{category}/{job-name}` — e.g., `jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts`. The path mirrors the matching scenario(s) under each SIEM root. Cloud jobs that span multiple services with no single semantic owner go under `jobs/{siem}/{provider}/multi-service/`. See [Jobs](#jobs) for the rationale.
- Pools: `pools/{pool-name}` — e.g., `pools/windows-auth-profiles`

For cloud providers the service directory (`aws/iam`, `aws/cloudtrail`) already provides
fine-grained grouping. For endpoint log sources (Sysmon, WinEventLog, auditd) an extra
event-category level groups related events together:

| Log source | Event category | Events covered |
|---|---|---|
| `windows/sysmon` | `process-create` | EID 1 |
| `windows/sysmon` | `network-connect` | EID 3 |
| `windows/sysmon` | `image-load` | EID 7 |
| `windows/sysmon` | `process-access` | EID 10 |
| `windows/sysmon` | `file-create` | EID 11 |
| `windows/sysmon` | `registry` | EID 12, 13, 14 |
| `windows/sysmon` | `dns-query` | EID 22 |
| `windows/wineventlog` | `account-management` | 4720, 4722, 4725, 4726, 4731–4733, 4738 |
| `windows/wineventlog` | `logon` | 4624, 4625, 4634, 4647, 4648 |
| `windows/wineventlog` | `process-tracking` | 4688, 4689 |
| `windows/wineventlog` | `privilege-use` | 4672, 4673 |
| `windows/wineventlog` | `object-access` | 4656, 4663, 4698 |

Current cloud scenarios stay flat at `{provider}/{service}/`. The service segment
(`aws/iam`, `aws/cloudtrail`) already provides fine-grained grouping.
Don't re-encode `mitre.tactics` in the path — those filter through the
`mitre:` block.

For cross-service analytics (e.g. AccessDenied bursts that span many
eventSources) and ConsoleLogin / `signin.amazonaws.com` events, use the
service segment that matches the analytic's semantic owner. AccessDenied
discovery scans file under `aws/iam/` (the analytic is IAM-identity-centric)
even when the underlying events span services.

Multi-event scenarios that span a category (e.g. a 4720 + 4732 sequence) belong in the
category that best describes the detection story. EventID membership is also expressed as
a tag (e.g. `eid10`, `eid4720`) for fine-grained search via `tracemill list scenarios --tags eid10`.

## Event Types

Event type files define the schema and engine metadata for a class of generated events. Every scenario that uses `emit:` with an `event_type:` field relies on an event type definition being present in the content hierarchy.

### Fields

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `event-type`. |
| `id` | Yes | Stable dotted identifier, e.g. `aws.cloudtrail`. Pattern: `^[a-zA-Z][a-zA-Z0-9._-]*$` |
| `version` | Yes | Version label, e.g. `v1`. |
| `full_name` | No | Human-readable display name. |
| `format` | No | Serialisation format. Default: `json`. |
| `xml_envelope` | No | Root element config for XML format: `element` (name, default `Event`) and `attributes` (key-value map). |
| `schema` | Yes | JSON Schema (draft 2020-12) for the event payload. Validated on every emitted event. |
| `defaults` | No | Default field values merged before scenario overrides. ExprStr supported. |
| `timestamp` | No | Payload field stamped with the logical clock on every emit. Omit to disable clock stamping. |
| `correlation` | Yes | Array of dotted payload paths that together uniquely identify a generated event instance in the SIEM. See below. |

### `correlation`

Declares which payload path(s) the engine uses to identify each generated event for SIEM correlation. Required on every event type.

Each entry is a dotted path into the event payload. The engine walks nested maps using these paths to extract the value; the key stored in the manifest (`correlation_values`) is the **full path** itself:

| Path | Stored key |
|---|---|
| `eventID` | `eventID` |
| `System.EventRecordID` | `System.EventRecordID` |
| `data.insertId` | `data.insertId` |

The SIEM adapter (e.g. the Splunk TA) maps that native path to the field name the SIEM indexes it under, so authors declare native payload paths and need not know SIEM field naming. By default the adapter searches the native dotted path as-is -- correct for JSON surfaces (Splunk indexes `data.insertId` as `data.insertId`). The one exception is the `windows.wineventlog` event type: Splunk's `XmlWinEventLog` extraction flattens nested fields to their leaf (`System.Computer` becomes a flat `Computer`), so the adapter searches the leaf for that event type.

Examples:

- Native UUID field: `correlation: [eventID]`
- Composite key: `correlation: [srcaddr, dstaddr, srcport, dstport, protocol]`
- Nested Windows fields: `correlation: [System.Computer, System.Channel, System.EventRecordID]`

Constraints:

- The declared paths must resolve against the payload produced by the scenario. If any intermediate map is missing or any leaf is empty, the event is recorded with a null correlation and excluded from the validation manifest.
- No two paths may be identical -- the registry rejects an event type with a duplicate correlation path (which would produce duplicate keys). Distinct paths that share a trailing segment (e.g. `System.Name` and `EventData.Name`) are fine; they store distinct full-path keys.
- The declared paths must survive SIEM ingestion unchanged. Do not use `tracemill_*` envelope fields — some ingestion tools strip unknown fields.

### XML attribute and text content convention

Event types with `format: xml` use a naming convention in their schema to control how the XMLFormatter renders elements, attributes, and text content:

- **`@key`** — renders as an XML attribute on the parent element.
- **`#text`** — renders as the text content of the parent element.

Keys without a prefix render as child elements (the default).

| Schema shape | XML output |
|---|---|
| `Provider: {"@Name": "Sysmon", "@Guid": "{...}"}` | `<Provider Name="Sysmon" Guid="{...}"/>` |
| `Data: {"@Name": "User", "#text": "SYSTEM"}` | `<Data Name="User">SYSTEM</Data>` |
| `TimeCreated: {"@SystemTime": "2026-04-15T10:00:00Z"}` | `<TimeCreated SystemTime="2026-04-15T10:00:00Z"/>` |
| `EventID: 4624` | `<EventID>4624</EventID>` |

When a map contains only `@`-prefixed keys (no `#text`, no child elements), the formatter produces a self-closing element. When `#text` is present alongside `@` keys, the text becomes the element body. When non-`@` keys coexist with `@` keys, the non-`@` keys render as child elements.

Arrays of maps with `@Name`/`#text` produce repeated elements — this is how `EventData.Data` items render:

```yaml
EventData:
  Data:
    - "@Name": SubjectUserSid
      "#text": S-1-5-18
    - "@Name": LogonType
      "#text": "2"
```

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-18</Data>
  <Data Name="LogonType">2</Data>
</EventData>
```

This convention is handled entirely by the XMLFormatter — it is not specific to any event type. Schema authors use it to produce native XML shapes (Windows Event Log, etc.) without requiring event-type-specific formatter logic.

### Adding a new event type

1. Create `event-types/{provider}/{service}/v1.yaml` (or the appropriate version).
2. Declare `correlation` pointing to the field(s) that uniquely identify each event instance in the SIEM.
3. Define a `schema` that matches real event payloads from that source. Use `additionalProperties: true` to stay compatible with source-specific variations.
4. Mark required fields conservatively — follow the source's own documentation. Fields that appear in all real events but are documented as optional should be kept optional.

```yaml
type: event-type
id: aws.cloudtrail
version: v1
full_name: AWS CloudTrail Management Event

timestamp: eventTime
correlation: [eventID]

defaults:
  eventVersion: "1.08"
  eventTime: gen.timestamp()

schema:
  $schema: https://json-schema.org/draft/2020-12/schema
  type: object
  required: [eventID, eventTime, eventSource, eventName]
  properties:
    eventID:
      type: string
      description: CloudTrail-generated GUID uniquely identifying each event.
    eventTime:
      type: string
    eventSource:
      type: string
    eventName:
      type: string
  additionalProperties: true
```

## Jobs

Job YAMLs that exercise scenarios against SIEM detections. The path
mirrors the scenarios tree under each SIEM root, so a job sits next to
the scenarios it consumes. The exact shape depends on the scenario kind:

| Scenario kind | Job path | Example |
|---|---|---|
| Endpoint (Sysmon, WinEventLog, auditd, ...) | `jobs/{siem}/{platform}/{log-source}/{event-category}/{job-slug}.yaml` | `jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts` |
| Cloud (AWS, GCP, Azure, ...) | `jobs/{siem}/{provider}/{service}/{job-slug}.yaml` | `jobs/splunk/aws/iam/aws-iam-accessdenied-discovery-events` |
| Cloud, multi-service (no single owner) | `jobs/{siem}/{provider}/multi-service/{job-slug}.yaml` | `jobs/splunk/aws/multi-service/aws-defense-evasion-impair-security-services` |

Cloud jobs stay flat at `{provider}/{service}/`. MITRE tactic / technique
is captured in the `mitre:` block, not the path.

Each Splunk job records the detection it validates in a `detection:` block --
provenance linking the job to its detective control: a Splunk security_content /
ESCU entry by `id` (the catalog UUID) + `name`, or a `custom` rule carrying its
`spl` inline. A job-level `detection:` is the default applied to every workload;
a workload can override it under `expectation.detection` for jobs that validate
different detections across workloads. Every `jobs/splunk/**` workload that has
an expectation resolves to a detection (CI-enforced).

For cloud jobs whose workloads span multiple service directories, apply
this rule in order:

1. **Semantic owner.** If the detection's logic is centered on a single
   service (identity-centric, GuardDuty-finding-centric, etc.), file the
   job under that service even when some workloads emit from other
   services. This mirrors the scenarios rule: AccessDenied discovery
   jobs live under `aws/iam/` because the analytic is IAM-centric.
2. **Otherwise, `multi-service/`.** When workloads span 2+ service
   directories and no single service is the analytic's semantic center,
   file under `jobs/{siem}/{provider}/multi-service/{job-slug}.yaml`.
   The bucket signals that the path does not name a service; readers
   open the file to see which services are exercised.

The SIEM segment (`splunk`, eventually `elastic`, `sentinel`, `chronicle` etc.) 
is the first axis because most users reach for jobs by SIEM
backend first ("show me the Splunk validation jobs"). Currently
populated for Splunk; sibling trees follow when those backends are in
scope.

## Tags and MITRE ATT&CK Metadata

Every content file supports a `tags` array and an optional `mitre` block.

### MITRE block

- **`mitre.tactics`** — one or more ATT&CK tactic slugs: `initial-access`, `execution`, `persistence`, `privilege-escalation`, `defense-evasion`,`defense-impairment`, `credential-access`, `discovery`, `lateral-movement`, `collection`, `exfiltration`, `impact`.
- **`mitre.techniques`** — one or more ATT&CK technique or sub-technique IDs (e.g., `T1078`, `T1562.008`, `T1485.001`).

The block is present on attack scenarios and omitted on benign scenarios — that absence is the canonical attack/benign signal, so an explicit `attack` / `benign` tag would just re-encode existing structure.

### Tags

Tags are an *index* on top of fields the corpus already encodes (path, `mitre:`, scenario slug). Use them only for cross-cutting dimensions the path doesn't capture:

| Dimension | When | Values |
|---|---|---|
| Identifier | when the file path doesn't already encode it | `eid<N>` for Windows event logs — the path uses semantic category names (`process-access`, `dns-query`), so the numeric tag is the bridge for `tracemill list scenarios --tags eid10`. **Skip when the filename slug IS the identifier**, e.g. `aws/cloudtrail/delete-trail.yaml` already encodes `delete-trail` in the path. |
| Threat | optional, multi | kebab-case campaign / actor / incident name (`3cx`, `solarwinds`, `apt29`, `lockbit`). Only when the entry specifically mirrors a named campaign — not for generic technique simulation. |
| Tool | optional, multi | kebab-case adversary tool name (`procdump`, `comsvcs`, `mimikatz`, `rclone`). Only when the scenario emits artifacts unique to a named tool (image path, call-trace DLL set, distinctive command-line). |
| CVE | optional, multi | `cve-YYYY-NNNNN` form, lowercase prefix to match the kebab-case convention (`cve-2023-29059`, not `CVE-2023-29059`). Only when the entry exercises behaviour tied to a specific assigned CVE. |

If none of those dimensions applies, omit `tags:` entirely. Most jobs end up here.

**Don't tag:**

- Anything already in the file path — provider, service, event-category, SIEM, vendor, product. All filterable via the path. (The scenario slug itself is treated separately by the Identifier row's "skip when the filename slug IS the identifier" rule. Threat / Tool / CVE values may legitimately overlap with the slug as substrings — `3cx` on `3cx-ioc-dns-query.yaml`, `procdump` on `lsass-dump-procdump.yaml` — because they're cross-cutting taxonomy dimensions, not slug duplicates.)
- Anything in the `mitre:` block — tactics or technique IDs. Filter via `mitre.tactics[]` / `mitre.techniques[]`.
- Attack / benign role — inferable from `mitre:` presence (`yq 'select(.mitre != null)'` for attacks, `select(.mitre == null)` for benigns).
- Validation tier on jobs — `workloads[].expectation.correlation` already encodes it structurally.
- Free-form behavioural hints (`auth`, `network`, `evasion`, `supply-chain`) — they overlap with MITRE vocabulary and have no agreed shared spelling.
- The SIEM platform (`splunk`) on a job — it's the first segment of the job path.

### Examples

Attack scenario tied to a named campaign with an assigned CVE:

```yaml
# scenarios/windows/sysmon/dns-query/3cx-ioc-dns-query.yaml
tags: [eid22, 3cx, cve-2023-29059]
mitre:
  tactics: [initial-access]
  techniques: [T1195.002]
```

Attack scenario where a specific tool produces the artifact:

```yaml
# scenarios/windows/sysmon/process-access/lsass-dump-procdump.yaml
tags: [eid10, procdump]
mitre:
  tactics: [credential-access]
  techniques: [T1003.001]
```

Benign control — no `mitre:` block (signals benign), only the identifier tag:

```yaml
# scenarios/windows/sysmon/process-access/lsass-access-routine.yaml
tags: [eid10]
```

Cloud-API scenario — the path encodes the action, no threat/tool/CVE applies, `tags:` is omitted entirely:

```yaml
# scenarios/aws/cloudtrail/delete-trail.yaml
mitre:
  tactics: [defense-evasion]
  techniques: [T1562.008]
```

Compound behavior maps to multiple tactics and techniques:

```yaml
# scenarios/aws/s3/put-bucket-lifecycle.yaml
mitre:
  tactics: [defense-evasion, impact]
  techniques: [T1562.008, T1485.001]
```

Job tagged with a campaign + CVE:

```yaml
# jobs/splunk/windows/sysmon/dns-query/3cx-supply-chain-attack-network-indicators.yaml
tags: [3cx, cve-2023-29059]
```

Typical job with no cross-cutting dimension — `tags:` field omitted entirely:

```yaml
# jobs/splunk/windows/wineventlog/logon/detect-password-spray-attempts.yaml
# (no `tags:` field)
mitre:
  tactics: [credential-access]
  techniques: ["T1110.003"]
```

## File Naming Conventions

- Kebab-case, lowercase: `brute-force.yaml`
- `.yaml` extension for all YAML content, no type suffixes (no `.pool.yaml` or `.job.yaml`)
- Describe the security behavior, not the log format: `lsass-dump-procdump.yaml`, not `eid10-lsass-access.yaml`
- Don't repeat the directory context: `lsass-dump-procdump.yaml`, not `sysmon-lsass-dump-procdump.yaml`
- Benign controls are named for what they actually model, not labelled with a `-benign` suffix: `lsass-access-routine.yaml`, `user-account-created.yaml`
- Variant suffix when needed to distinguish tools or techniques: `lsass-dump-comsvcs.yaml`, `brute-force-slow.yaml`

## Job References

Jobs reference scenarios and pools by content ID. The same disambiguation rule applies everywhere: values starting with `./`, `/`, or `~` are treated as file paths; everything else is a content ID resolved through the content layers.

```yaml
type: job

workloads:
  - scenario: scenarios/aws/cloudtrail/delete-trail
    bindings:
      account_id: ref.account_id

  - scenario: scenarios/aws/iam/create-access-key
    bindings:
      account_id: ref.account_id
```

## Releasing

Releases are driven by the `release.yml` GitHub Actions workflow, triggered by pushing a `lib-v*` tag.

```bash
git tag lib-v2026.03.21
git push origin lib-v2026.03.21
```

The workflow:
1. Creates a `library.tar.gz` archive (excluding `.git`, `.github`, `LICENSE`, `README.md`, `library.json`)
2. Computes the SHA-256 digest
3. Reads `min_cli_version` from `library.json`
4. Builds a `version.json` manifest with version, sha256, min_cli_version, and published_at
5. Uploads to S3: versioned archive (`library/{version}/`), latest pointer (`library/latest/`), and manifest (`library/version.json`)

Same-day re-releases use a `.N` suffix: `lib-v2026.03.21.1`.

The `min_cli_version` field in `library.json` should be bumped only when new content requires CLI features not present in older versions (new generator, new YAML field, etc.).

## License

Apache 2.0
