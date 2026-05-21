# OpenClaw Integration

OpenClaw support uses the same local proxy idea as Codex, but JSON config formats vary across installs.

## Commands

```bash
qise doctor
qise protect openclaw
qise status
qise restore openclaw
```

## What Qise Looks For

Qise currently checks these paths:

```text
~/.openclaw/openclaw.json
~/.openclaw/config.json
~/.config/openclaw/config.json
~/.claw/config.json
```

It rewrites base-url-like fields to `http://127.0.0.1:8822/agent/openclaw/v1`. Qise metadata is stored in `~/.qise/state.json`, not in the OpenClaw config, because OpenClaw rejects unknown root keys.

## Validation

After protect:

```bash
qise scan agent-config openclaw
qise status
```

Because OpenClaw config layouts may differ, inspect the generated backup and patch diff under `~/.qise/backups/openclaw/...` before broad use.
