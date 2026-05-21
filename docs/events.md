# Events

Qise writes local JSONL security events to `~/.qise/events.jsonl` by default.

## Commands

```bash
qise events --limit 10
qise events --limit 10 --json
qise events --since 1h
qise events --stage runtime
```

## Schema

Each event includes:

```text
id
schema_version
timestamp
stage
source
agent
action
risk.category
risk.severity
risk.confidence
decision.verdict
decision.mode
decision.blocked_by
evidence
recommendation
correlation_id
raw_ref
```

## Sources

Current MVP event sources:

| Source | Meaning |
| --- | --- |
| `scan` | `qise scan ...` preflight results |
| `cli-check` | `qise check ...` guard checks |
| `observer` | `qise run ...` runtime process/file/network observations |
| `proxy` | Python proxy interception decisions |
| `bridge` | Python bridge guard decisions |

## Privacy

Events store compact snippets and rule evidence, not full model transcripts.
