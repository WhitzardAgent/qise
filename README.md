<div align="center">

# Qise

**Lightweight local security for AI coding agents.**

Protect Codex, OpenClaw, and OpenAI-compatible agents from dangerous commands, secret leaks, unsafe file access, suspicious network requests, prompt injection, and risky third-party skills.

[中文](./README_CN.md) | [Quickstart](./docs/quickstart.md) | [Install](./docs/install.md) | [Events](./docs/events.md) | [Privacy](./docs/privacy.md)

</div>

---

## 30-Second Demo

Run a local, no-real-Agent demo:

```bash
git clone https://github.com/opq-qise/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
bash ./scripts/demo_mvp.sh
```

You will see Qise protect a temporary Codex config, block a dangerous command, write a security event, and restore the config.

## What Qise Does Today

Qise MVP has three product surfaces:

| Surface | What it does | Current status |
| --- | --- | --- |
| `qise protect codex` | Backs up Codex config, routes it through local Qise proxy, restores on demand | Verified MVP |
| `qise scan skill/mcp` | Preflight scans third-party skills and MCP configs before use | Verified MVP |
| `qise events` | Shows explainable local JSONL security events with evidence and recommendations | Verified MVP |

Qise is not a model provider. In proxy mode it sits between your Agent and the model API the Agent already uses:

```text
Agent -> Qise local proxy -> upstream model API
```

`qise protect codex` first tries to infer the upstream API and API-key environment variable from Codex's existing config. Use `--base-url <provider-url>` only when inference fails or for custom OpenAI-compatible Agents.

## Install

Source install is the recommended path until the first PyPI release:

```bash
git clone https://github.com/opq-qise/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
```

See [docs/install.md](./docs/install.md) for pipx/source options and troubleshooting.

## Quick Start

```bash
qise doctor
qise status
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
qise scan mcp examples/mcp-dangerous.json || true
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 10
```

Protect a real Codex install:

```bash
qise protect codex
qise status
qise events --limit 10
qise restore codex
qise stop
```

`protect` modifies the Agent config only after making a backup under `~/.qise/backups/...`.

## Demo Scripts

```bash
./scripts/demo_mvp.sh   # protect/check/events/restore with a temporary fake Codex config
./scripts/demo_scan.sh  # preflight scan safe and dangerous fixtures
```

These scripts are safe to run repeatedly. They use temporary `QISE_HOME` and `QISE_AGENT_HOME` directories.
You can also use the Python wrappers:

```bash
python ./scripts/demo_mvp.py
python ./scripts/demo_scan.py
```


## Supported Agents

| Agent | Command | Notes |
| --- | --- | --- |
| Codex | `qise protect codex` | Primary verified MVP path |
| OpenClaw | `qise protect openclaw` | JSON config patcher implemented; validate against your local install |
| Custom OpenAI-compatible | `qise protect custom --base-url <url>` | Manual proxy target |
| Claude Code | `qise protect claude-code --experimental` | Experimental only; native Anthropic `/v1/messages` proxy is not complete yet |

## Security Events

All product events use one local JSONL schema:

```bash
qise events --limit 10
qise events --limit 10 --json
```

Each event includes `id`, `stage`, `source`, `risk.category`, `decision.verdict`, `evidence`, `recommendation`, and `correlation_id`.

## Local-First Privacy

Qise stores product state under `~/.qise/` by default:

```text
~/.qise/state.json
~/.qise/events.jsonl
~/.qise/backups/
~/.qise/logs/
```

Events store compact evidence snippets, not full model traffic. See [docs/privacy.md](./docs/privacy.md).

## Verified Scope

Qise MVP currently verifies local CLI/product flows: protect/restore, proxy interception for OpenAI-compatible chat-completions traffic, preflight scan, and explainable events. OS-level process observation, packaged desktop app distribution, and native Claude Code Anthropic API interception are later phases.

## Learn More

- [Quickstart](./docs/quickstart.md)
- [Install](./docs/install.md)
- [Codex integration](./docs/codex.md)
- [OpenClaw integration](./docs/openclaw.md)
- [Claude Code status](./docs/claude-code.md)
- [Preflight scan](./docs/preflight-scan.md)
- [Events](./docs/events.md)
- [Troubleshooting](./docs/troubleshooting.md)
