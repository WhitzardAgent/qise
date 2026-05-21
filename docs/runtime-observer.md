# Runtime Observer

`qise run` is the first lightweight implementation of Qise Observer. It runs an Agent command as a child process and records what happened around that process without requiring kernel extensions.

## Basic Usage

```bash
qise run --agent codex -- codex
qise events --stage runtime --limit 10
```

For a safe smoke test:

```bash
mkdir -p /tmp/qise-runtime-demo
qise run --agent demo --cwd /tmp/qise-runtime-demo -- python -c 'from pathlib import Path; print("ok"); Path("out.txt").write_text("hello")'
qise events --stage runtime --json
```

## What It Records

- Agent process command, pid, working directory, exit code, and duration.
- Sampled child process command lines.
- stdout/stderr tail summaries.
- Before/after working directory file diff.
- Best-effort network endpoints using `lsof` when available.
- A `correlation_id` stored in the runtime event and exported to the child process as `QISE_RUNTIME_CORRELATION_ID`.

## Options

```bash
qise run --agent openclaw -- openclaw gateway
qise run --agent codex --cwd /path/to/project -- codex
qise run --agent demo --no-file-snapshot -- python script.py
qise run --agent demo --poll-interval 0.5 -- python script.py
```

## Current Limits

This is a user-space wrapper. It observes processes started under `qise run`; it does not see unrelated already-running Agent processes, kernel-level file access, or every short-lived network connection. Phase 7 sandbox work should deepen this for dynamic Skill testing.
