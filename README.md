# Tracemill Content Library

Open source scenarios, jobs, and pools for the [Tracemill](https://tracemill.io) telemetry generation engine.

This library is distributed to end users via `tracemill update` and installed to `~/.tracemill/library/`. Users should not edit the installed copy directly — the entire directory is replaced on each update.

## Content Types

**Scenarios** are atomic and self-contained. A scenario is a single YAML file with no external dependencies — it uses generators, refs, and state, all defined inline.

**Jobs** wire scenarios together with pools, bindings, and concurrency settings. Jobs reference scenarios and shared pools by content ID.

**Pools** are reusable data sources (IP ranges, string lists, CSV references) that jobs bind to scenarios at runtime.

**Event types** declare the schema and engine metadata for a class of generated events. Scenarios reference event types by `id@version` (e.g. `aws.cloudtrail@v1`); the engine validates every emitted event against the declared JSON Schema.

## Repository Structure

Content is organized by type at the top level, then by provider and service.

```
scenarios/
  aws/
    cloudtrail/
      delete-trail.yaml                     # type: scenario
    iam/
      create-access-key.yaml                # type: scenario
      update-login-profile.yaml             # type: scenario
    s3/
      put-bucket-lifecycle.yaml             # type: scenario
event-types/
  aws/
    cloudtrail/
      v1.yaml                              # type: event-type
pools/
  threat-ips.yaml                          # type: pool (ip_range)
jobs/
  aws/
    brute-force.yaml                       # type: job
```

The `type:` field in each YAML file identifies what it is. The tree structure provides organization, not type disambiguation.

## Content IDs

Every file has a content ID: its path from the repository root, minus the `.yaml` extension. Content IDs are how users and jobs reference content.

| File | Content ID |
|---|---|
| `scenarios/aws/cloudtrail/delete-trail.yaml` | `scenarios/aws/cloudtrail/delete-trail` |
| `scenarios/aws/iam/create-access-key.yaml` | `scenarios/aws/iam/create-access-key` |
| `scenarios/aws/s3/put-bucket-lifecycle.yaml` | `scenarios/aws/s3/put-bucket-lifecycle` |

Content IDs are stable identifiers. Users reference them in jobs, scripts, and CI pipelines. Renaming or moving a file is a breaking change.

## Usage

```bash
# Run a scenario by content ID
$ tracemill run scenarios/aws/cloudtrail/delete-trail

# Run with explicit type validation
$ tracemill run scenario scenarios/aws/iam/create-access-key

# List available content
$ tracemill list scenarios
```

## Directory Taxonomy

The directory path is part of the content ID, so the taxonomy is a contract. Follow these conventions:

- Cloud scenarios: `scenarios/{provider}/{service}/{scenario-name}` — e.g., `scenarios/aws/iam/create-access-key`
- Endpoint scenarios: `scenarios/{platform}/{log-source}/{scenario-name}` — e.g., `scenarios/windows/eventlog/lateral-movement`
- Network scenarios: `scenarios/{protocol-or-domain}/{scenario-name}` — e.g., `scenarios/dns/tunneling`
- Jobs: `jobs/{provider}/{job-name}` — e.g., `jobs/aws/brute-force`
- Pools: `pools/{pool-name}` — e.g., `pools/threat-ips`

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
| `schema` | Yes | JSON Schema (draft 2020-12) for the event payload. Validated on every emitted event. |
| `defaults` | No | Default field values merged before scenario overrides. ExprStr supported. |
| `timestamp` | No | Payload field stamped with the logical clock on every emit. Omit to disable clock stamping. |
| `correlation` | Yes | Array of payload field names that together uniquely identify a generated event instance in the SIEM. See below. |

### `correlation`

Declares which payload field(s) the engine uses to identify each generated event for SIEM correlation. Required on every event type.

For event types with a native UUID field: `correlation: [eventID]`

For event types without a native UUID, declare the combination of fields that makes each event uniquely identifiable: `correlation: [srcaddr, dstaddr, srcport, dstport, protocol]`

The declared fields must be part of the standard schema and survive SIEM ingestion unchanged. Do not use `tracemill_*` envelope fields — some ingestion tools strip unknown fields.

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

## Tags and MITRE ATT&CK Metadata

Every content file supports `tags` and an optional `mitre` block for ATT&CK mapping:

```yaml
tags: [aws, cloudtrail]
mitre:
  tactics: [defense-evasion]
  techniques: [T1562.008]
```

- **`tags`** — free-form labels for filtering (`tracemill list scenarios --tags aws`). Use lowercase kebab-case. Common tags: provider (`aws`, `gcp`), service (`iam`, `s3`, `cloudtrail`), attack category (`brute-force`, `exfiltration`).
- **`mitre.tactics`** — one or more ATT&CK tactic slugs: `initial-access`, `execution`, `persistence`, `privilege-escalation`, `defense-evasion`, `credential-access`, `discovery`, `lateral-movement`, `collection`, `exfiltration`, `impact`.
- **`mitre.techniques`** — one or more ATT&CK technique or sub-technique IDs (e.g., `T1078`, `T1562.008`, `T1485.001`).

A scenario can map to multiple tactics and techniques when it covers compound behavior:

```yaml
# scenarios/aws/s3/put-bucket-lifecycle.yaml
tags: [aws, s3]
mitre:
  tactics: [defense-evasion, impact]
  techniques: [T1562.008, T1485.001]
```

## File Naming Conventions

- Kebab-case, lowercase: `brute-force.yaml`
- `.yaml` extension for all YAML content, no type suffixes (no `.pool.yaml` or `.job.yaml`)
- Action-oriented, descriptive names: `brute-force.yaml`, `credential-stuffing.yaml`
- Don't repeat the directory context: `brute-force.yaml`, not `cloudtrail-brute-force.yaml`
- Variant suffix when needed: `brute-force-slow.yaml`

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
