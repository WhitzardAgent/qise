# Quickstart

This quickstart gives you a local Qise MVP loop: diagnose, scan, block a dangerous tool call, view events, and optionally protect Codex.

## Install

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
```

## Run the Safe Demo

```bash
bash ./scripts/demo_mvp.sh
```

The script uses temporary `QISE_HOME` and `QISE_AGENT_HOME` directories, so it does not touch your real `~/.codex` config.

## Manual MVP Loop

```bash
qise doctor
qise status
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
qise scan mcp examples/mcp-dangerous.json || true
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 10
qise events --limit 10 --json
```

## Enable Local SLM

Qise works in rule-only mode by default. To enable the second-layer local 4B SLM:

```bash
qise slm start
qise slm status
```

Advanced options:

```bash
qise slm start --model llama3.2:3b
qise slm start --base-url http://localhost:8000/v1 --model my-security-model
qise slm stop --keep-server
```

Disable the SLM layer:

```bash
qise slm stop
```

Restart Qise protection after changing SLM state if the proxy was already running.

## Protect Codex

If Codex is installed and has a config, run:

```bash
qise protect codex
qise status
qise restore codex
qise stop
```

`qise protect codex` backs up your config under `~/.qise/backups/codex/...` before patching it.

## When `protect` Needs `--base-url`

Qise first tries to infer the upstream model API from the Agent config. If inference fails, pass the model API your Agent normally uses:

```bash
qise protect codex --base-url https://api.openai.com/v1
```

For non-OpenAI providers, use that provider's OpenAI-compatible base URL.
