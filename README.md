# Tracemill Content Library

Open source scenarios, jobs, and pools for the [Tracemill](https://tracemill.io) telemetry generation engine.

This library is distributed to end users via `tracemill update` and installed to `~/.tracemill/library/`. Users should not edit the installed copy directly — the entire directory is replaced on each update.

## Content Types

**Scenarios** are atomic and self-contained. A scenario is a single YAML file with no external dependencies — it uses generators, refs, and state, all defined inline.

**Jobs** wire scenarios together with pools, sinks, bindings, and concurrency settings. Jobs reference scenarios and shared pools by content ID.

**Pools** are reusable data sources (IP ranges, string lists, CSV references) that jobs bind to scenarios at runtime.

## Repository Structure

Within each domain, `scenarios/` holds scenario files, job files sit at the domain level, and `resources/pools/` at the root holds shared pools.

```
aws/
  scenarios/
    cloudtrail/
      brute-force.yaml                      # type: scenario
      exfiltration.yaml                     # type: scenario
    s3/
      public-bucket-access.yaml             # type: scenario
  brute-force.yaml                          # type: job
  full-coverage.yaml                        # type: job
windows/
  scenarios/
    eventlog/
      lateral-movement.yaml                 # type: scenario
      credential-dumping.yaml               # type: scenario
  detection-sweep.yaml                      # type: job
resources/
  pools/
    threat-ips.yaml                         # type: pool
    common-usernames.yaml                   # type: pool
```

The `type:` field in each YAML file identifies what it is. The tree structure provides organization, not type disambiguation.

## Content IDs

Every file has a content ID: its path from the repository root, minus the `.yaml` extension. Content IDs are how users and jobs reference content.

| File | Content ID |
|---|---|
| `aws/scenarios/cloudtrail/brute-force.yaml` | `aws/scenarios/cloudtrail/brute-force` |
| `aws/brute-force.yaml` | `aws/brute-force` |
| `resources/pools/threat-ips.yaml` | `resources/pools/threat-ips` |

Content IDs are stable identifiers. Users reference them in jobs, scripts, and CI pipelines. Renaming or moving a file is a breaking change.

## Usage

```bash
# Run a scenario
$ tracemill run aws/scenarios/cloudtrail/brute-force
# → resolved: ~/.tracemill/library/aws/scenarios/cloudtrail/brute-force.yaml (scenario)

# Run a job
$ tracemill run aws/brute-force
# → resolved: ~/.tracemill/library/aws/brute-force.yaml (job)

# Run all jobs under a domain
$ tracemill run aws/

# Run all scenarios in a directory
$ tracemill run scenario aws/scenarios/cloudtrail/

# Filter by tags
$ tracemill run aws/ --tags brute-force

# List available content
tracemill list scenarios
tracemill list jobs --tags aws
```

## Directory Taxonomy

The directory path is part of the content ID, so the taxonomy is a contract. Follow these conventions:

- Cloud: `{provider}/scenarios/{service}/{scenario-name}` — e.g., `aws/scenarios/cloudtrail/brute-force`
- Endpoint: `{platform}/scenarios/{log-source}/{scenario-name}` — e.g., `windows/scenarios/eventlog/lateral-movement`
- Network: `{protocol-or-domain}/scenarios/{scenario-name}` — e.g., `dns/scenarios/tunneling`
- Jobs: `{provider}/{job-name}` — e.g., `aws/brute-force`
- Shared pools: `resources/pools/{pool-name}` — e.g., `resources/pools/threat-ips`

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
id: aws-brute-force

pools:
  - id: threat-ips
    path: resources/pools/threat-ips             # content ID → shared pool
  - id: local-data
    path: ./pools/custom.yaml                    # file path → relative to job file

workloads:
  - scenario: aws/scenarios/cloudtrail/brute-force
    bindings:
      source_ip: pool.threat-ips
```

## License

Apache 2.0
