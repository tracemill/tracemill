# Tracemill

Tracemill is a CLI engine for stateful, high-fidelity, scalable telemetry generation. Its primary use cases are detection validation and stress-testing observability and security systems.

YAML config files define generation pipelines that produce realistic, correlated event streams across configurable resource pools, scenarios, and sinks.

## Concepts

- **Pool** — a named set of resources (IP ranges, user identities, hostnames, CSV data) drawn from during generation
- **Scenario** — a sequence of event steps with shared state, field expressions, and correlation rules
- **Sink** — output destination: stdout, TCP, or HTTP
- **Job** — wires multiple scenarios together with pools, sinks, concurrency, and rate limits

## Invocation

Run a standalone scenario:

```bash
tracemill run --scenario ./scenario.yaml
```

Run a multi-workload job:

```bash
tracemill run --job ./job.yaml
```

Point to a custom event-type catalog:

```bash
tracemill run --scenario ./scenario.yaml --events ./catalog/event-types
```

Dry-run (validate config without emitting events):

```bash
tracemill run --job ./job.yaml --dry-run
```
