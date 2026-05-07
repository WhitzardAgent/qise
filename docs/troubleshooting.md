# Troubleshooting

## `qise protect codex` Cannot Infer Upstream

Pass the upstream model API manually:

```bash
qise protect codex --base-url https://api.openai.com/v1
```

Use the provider URL your Agent normally calls.

## Proxy Port Already In Use

Check status:

```bash
qise status
```

Stop Qise-managed services:

```bash
qise stop
```

If another process owns the port, either stop that process or change the proxy port in `shield.yaml`.

## Dangerous Demo Commands Return Non-Zero

That is expected. `BLOCK` exits non-zero so scripts can fail closed. In docs and demo scripts we use `|| true` for expected blocks.

## Restore Real Agent Config

```bash
qise restore codex
qise restore openclaw
qise restore all
```

Backups remain under `~/.qise/backups/`.

## Clean Demo State

Demo scripts print their temporary directory and clean it automatically. For manual tests, use a temp home:

```bash
export QISE_HOME=$(mktemp -d)
export QISE_AGENT_HOME=$(mktemp -d)
```
