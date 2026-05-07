# Preflight Scan

Preflight scan helps you inspect third-party Agent assets before enabling them.

## Scan Skills

```bash
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
```

Current checks include:

- Hidden instruction override patterns
- `curl | bash` and `wget | sh`
- postinstall/setup scripts
- suspicious callback domains
- sensitive file references such as `.env` and SSH keys
- possible secret harvesting
- base64/hex-like obfuscation

## Scan MCP Configs

```bash
qise scan mcp examples/mcp-safe.json
qise scan mcp examples/mcp-dangerous.json || true
```

Current checks include remote download execution, shell chaining, sensitive env exposure, and suspicious paths/domains.

## Scan Agent Config

```bash
qise scan agent-config codex
qise scan agent-config openclaw
```

This checks whether the Agent config points through Qise proxy and whether the local Qise protection state has a readable backup.

## Events

Every scan writes a `preflight` event:

```bash
qise events --limit 10
qise events --limit 10 --json
```
