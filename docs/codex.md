# Codex Integration

Codex is the primary verified MVP path for `qise protect`.

## What Qise Changes

`qise protect codex`:

1. Locates Codex config, usually `~/.codex/config.toml`.
2. Infers the active provider `base_url` and `env_key`.
3. Creates a backup under `~/.qise/backups/codex/<timestamp>/`.
4. Adds a `qise-proxy` provider pointing at `http://127.0.0.1:8822/v1`.
5. Starts or records Qise proxy/bridge services.

## Commands

```bash
qise doctor
qise protect codex
qise status
qise events --limit 10
qise restore codex
qise stop
```

## If Upstream Cannot Be Inferred

```bash
qise protect codex --base-url https://api.openai.com/v1
```

Use the API base URL your Codex provider normally uses.

## Safety

Restore is always available from the recorded backup:

```bash
qise restore codex
```

Backups are kept after restore for auditability.
