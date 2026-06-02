<div align="center">

# Qise

**Local-first security for AI coding agents.**

Qise helps you run agents such as Codex, OpenClaw, Claude Code, and custom agents with a local safety layer that can scan integrations, route model traffic through a guard proxy, block risky actions, and leave an explainable event trail.

[中文](./README_CN.md) | [Quickstart](./docs/quickstart.md) | [Install](./docs/install.md) | [Architecture](./docs/architecture.md) | [Privacy](./docs/privacy.md)

</div>

---

## What Qise Is

AI coding agents can read files, run shell commands, call MCP servers, install skills, use memories, and send data to model APIs. That power is useful, but it also creates a new security boundary: a poisoned tool description, malicious skill, prompt injection, unsafe command, or accidental secret leak can turn into real local damage.

Qise is a lightweight local security layer for that boundary. It is not a model provider and it does not replace your agent. It runs on your machine and sits beside the agent you already use.

In the common proxy mode, the flow is:

```text
AI Agent -> Qise local proxy -> your existing model API
```

Qise can:

- Check tool calls before they reach your system.
- Block dangerous commands such as destructive shell operations.
- Warn about suspicious file, network, credential, and exfiltration behavior.
- Scan skills, MCP configs, and agent configs before you trust them.
- Add local security context to agent/model requests.
- Record local JSONL security events with evidence and recommendations.
- Optionally use a local small language model, through Ollama or another OpenAI-compatible endpoint, as a second semantic review layer.
- Provide both a CLI and a desktop UI over the same product engine.

Qise is local-first. Product state, backups, and events are stored under `~/.qise/` by default. Event records store compact evidence snippets, not full model traffic.

## Who It Is For

Use Qise if you:

- Use an AI coding agent and want a safety layer before commands, files, network requests, or tool calls hit your machine.
- Install third-party skills or MCP servers and want a preflight scan before enabling them.
- Want a local event log that explains what was blocked or warned about.
- Build agents and want SDK-style guard integrations for frameworks such as LangGraph or OpenAI Agents SDK.
- Want a desktop control panel for protection status, preflight scans, events, guard modes, local SLM setup, backups, and diagnostics.

## Current Status

Qise is currently an alpha/MVP project. Source install is the recommended path until a PyPI release is available.

| Area | What works now | Status |
| --- | --- | --- |
| CLI | `doctor`, `status`, `agents`, `scan`, `check`, `events`, `protect`, `restore`, `stop`, `slm`, `run` | Active MVP |
| Proxy protection | Local proxy for OpenAI-compatible `/v1/chat/completions` traffic and Anthropic `/v1/messages` traffic | Active MVP |
| Preflight scan | Skill, MCP config, agent config, and detected agent asset scanning | Active MVP |
| Guard engine | 14 guards across ingress, egress, and output pipelines | Active MVP |
| Event log | Local JSONL events with risk, evidence, verdict, recommendation, and correlation IDs | Active MVP |
| Local SLM | Optional semantic review layer through Ollama or custom OpenAI-compatible endpoint | Active MVP |
| Runtime Observer | User-space wrapper for process, stdout/stderr, file diff, and best-effort network evidence | MVP |
| Desktop app | Tauri 2 + React UI that calls the same Qise CLI | Source-build MVP |
| Claude Code | Native Anthropic `/v1/messages` proxy path with request/response parsing, security-context injection, and streaming `tool_use` checks | Active MVP |

## Project Shape

The repository is split into a few clear layers:

```text
src/qise/              Python product engine, CLI, proxy, bridge, guards, adapters
src/qise/guards/       Prompt, command, credential, filesystem, network, exfil, and other guards
src/qise/product/      User-facing product flows: protect, restore, scan, status, doctor, events, SLM
src/qise/proxy/        OpenAI-compatible and Anthropic Messages local proxy and streaming support
src/qise/bridge/       Local bridge used by the desktop UI for guard state
src/qise/adapters/     SDK/framework snippets and integrations
src-ui/                React + TypeScript desktop frontend
src-tauri/             Tauri 2 Rust desktop shell and IPC commands
src-proxy/             Rust proxy experiment/runtime components
data/                  Threat patterns, security contexts, prompt examples
docs/                  Deeper installation, architecture, privacy, event, and integration docs
examples/              Safe and dangerous sample skills, MCP configs, and agent examples
tests/                 Python test suite for guards, proxy, CLI, and product flows
```

The important design point is that the desktop app does not implement a separate security engine. It calls the same Python `qise` CLI through Tauri IPC, so CLI and UI behavior stay aligned.

## Requirements

For the CLI:

- Python 3.11 or newer.
- macOS or Linux shell for the current demo scripts.
- A real agent install only if you want to protect a real Codex/OpenClaw/Claude Code/custom agent.

For the desktop app from source:

- The CLI requirements above.
- Node.js 18 or newer.
- Rust stable toolchain.
- PyInstaller only when building a bundled desktop runtime.

## Install From Source

Run these commands from a terminal:

```bash
git clone https://github.com/opq-qise/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
```

What each command does:

| Command | Why you run it |
| --- | --- |
| `git clone ...` | Downloads the Qise source code. |
| `cd qise` | Moves into the project directory. |
| `python3.11 -m venv .venv` | Creates an isolated Python environment for Qise. |
| `source .venv/bin/activate` | Activates that environment so `python` and `pip` use it. |
| `pip install -e ".[proxy]"` | Installs Qise in editable mode with proxy runtime dependencies. |
| `qise doctor` | Checks Python, Qise import, config, local ports, event log, optional SLM, and detected agents. |

For development and tests, install the dev extra:

```bash
pip install -e ".[dev,proxy]"
```

## First Safe Demo

If this is your first time using Qise, start here. This demo uses temporary directories and does not touch your real Codex config.

```bash
bash ./scripts/demo_mvp.sh
```

The demo does the following:

| Step | What happens |
| --- | --- |
| Doctor | Runs readiness checks. |
| Protect fake Codex | Creates and patches a temporary Codex config. |
| Status | Shows Qise services, protected agent state, event path, and SLM state. |
| Dangerous check | Runs `qise check bash '{"command":"rm -rf /"}'` and expects Qise to block it. |
| Events | Prints the local security event explaining the block. |
| Restore | Restores the temporary fake Codex config. |

You can also run the preflight scan demo:

```bash
bash ./scripts/demo_scan.sh
```

That scans a safe skill, a dangerous skill, and a dangerous MCP config, then shows the events Qise recorded.

## Manual CLI Walkthrough

After installation, this sequence gives you a quick feel for the product:

```bash
qise version
qise doctor
qise status
qise agents
qise scan skill examples/skills/safe
qise scan skill examples/skills/dangerous || true
qise scan mcp examples/mcp-dangerous.json || true
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 10
```

What these commands mean:

| Command | What it does |
| --- | --- |
| `qise version` | Prints the installed Qise version. |
| `qise doctor` | Runs readiness diagnostics and tells you what is missing or only partially configured. |
| `qise status` | Shows active services, protected agents, detected agents, SLM state, and recent event counts. |
| `qise agents` | Detects supported local agent CLIs/configs, such as Codex, OpenClaw, or Claude Code. |
| `qise scan skill ...` | Scans a skill directory or file before you trust/install it. |
| `qise scan mcp ...` | Scans an MCP JSON/YAML config for risky commands, exposed env vars, injection text, and suspicious callbacks. |
| `qise check bash ...` | Runs one guard pipeline check manually against a tool call. The example should be blocked. |
| `qise events --limit 10` | Shows the most recent local security events in a readable format. |

The `|| true` suffix is used in the examples because a block is represented as a non-zero exit code. That is expected for dangerous test inputs.

For machine-readable output:

```bash
qise status --json
qise events --limit 10 --json
qise scan mcp examples/mcp-dangerous.json --json || true
```

## Protect A Real Agent

Protection means Qise backs up your agent config, patches the agent's model base URL to point at the local Qise proxy, starts managed Qise services, and records the backup path so you can restore later.

Before protecting a real agent, make sure:

- Your agent already works without Qise.
- Your model provider API key is still available in the environment your agent uses, for example `OPENAI_API_KEY` for OpenAI-compatible agents or `ANTHROPIC_API_KEY` for Claude Code.
- You know the upstream model API base URL if Qise cannot infer it from the agent config.

Protect Codex:

```bash
qise protect codex
qise status
qise events --limit 10
```

What happens:

| Command | What it does |
| --- | --- |
| `qise protect codex` | Locates Codex config, infers the original upstream API if possible, creates a backup under `~/.qise/backups/codex/...`, patches Codex to use Qise proxy, and starts the proxy/bridge services. |
| `qise status` | Confirms which agents are protected and where the backup/config/event files are. |
| `qise events --limit 10` | Shows recent blocks and warnings created by scan, proxy, CLI check, or runtime observer flows. |

If Qise cannot infer the upstream provider, pass it explicitly:

```bash
qise protect codex --base-url https://api.openai.com/v1
```

Protect OpenClaw:

```bash
qise protect openclaw
```

Protect Claude Code:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
qise protect claude-code --base-url https://api.anthropic.com
qise status
```

What happens:

| Command | What it does |
| --- | --- |
| `export ANTHROPIC_API_KEY=...` | Keeps your Anthropic provider key available to Claude Code and to the Qise-managed proxy process. If you already use an `apiKeyHelper`, keep using it; Qise can also preserve the key sent by Claude Code. |
| `qise protect claude-code --base-url https://api.anthropic.com` | Backs up `~/.claude/settings.json`, sets `env.ANTHROPIC_BASE_URL` to the local Qise proxy, records the original Anthropic upstream, and starts Qise services. |
| `qise status` | Confirms Claude Code is protected and shows the backup path. |

Protect a custom OpenAI-compatible agent:

```bash
qise protect custom --base-url https://api.openai.com/v1
```

For a custom agent, Qise starts the proxy and prints the local proxy URL. Point your agent's base URL to:

```text
http://127.0.0.1:8822/v1
```

Restore and stop:

```bash
qise restore codex
qise restore all
qise stop
```

| Command | What it does |
| --- | --- |
| `qise restore codex` | Restores Codex config from the Qise backup record. |
| `qise restore all` | Restores every agent currently recorded as protected by Qise. |
| `qise stop` | Stops Qise-managed proxy and bridge background services. |

Qise keeps backups under `~/.qise/backups/` after restore so you can inspect what changed.

## CLI Command Map

| Command | Use it when you want to |
| --- | --- |
| `qise init` | Generate a local `shield.yaml` config file. |
| `qise doctor` | Diagnose local readiness. |
| `qise status` | See service, protection, SLM, agent, and event status. |
| `qise agents` | Detect supported installed agents. |
| `qise protect <agent>` | Back up and route an agent through Qise. |
| `qise restore <agent|all>` | Restore agent config modified by Qise. |
| `qise stop` | Stop Qise-managed background services. |
| `qise scan all` | Scan detected agent assets automatically. |
| `qise scan agent <agent>` | Scan one agent's config, skill files, and MCP candidates. |
| `qise scan skill <path>` | Scan a skill directory or file. |
| `qise scan mcp <path>` | Scan an MCP JSON/YAML config. |
| `qise scan agent-config <agent>` | Check whether an installed agent config is routed through Qise and still matches Qise state. |
| `qise check <tool> <json>` | Manually run a guard pipeline check. |
| `qise events` | Read local security events. |
| `qise slm start/status/stop` | Configure or disable the optional local SLM review layer. |
| `qise run --agent <name> -- <cmd>` | Run a command under the Runtime Observer. |
| `qise guards` | List registered guards, pipelines, strategies, and modes. |
| `qise context <tool>` | Preview security context text for a tool. |
| `qise proxy start` | Start the local OpenAI-compatible/Anthropic proxy manually. |
| `qise bridge start` | Start the local bridge used by desktop/guard control flows. |
| `qise serve --transport stdio` | Start Qise as an MCP server. |
| `qise adapters <name>` | Print SDK integration snippets for supported frameworks. |

## Guard Pipeline

Qise runs checks through three pipelines:

| Pipeline | Direction | Example risks |
| --- | --- | --- |
| Ingress | World to agent | Prompt injection, tool poisoning, context poisoning, supply-chain instructions. |
| Egress | Agent to world | Dangerous shell commands, unsafe file access, risky network calls, exfiltration, resource abuse, tool policy violations. |
| Output | Agent to user/logs | Credential leaks, sensitive output, audit signals. |

The current guard set includes:

| Guard | Main purpose |
| --- | --- |
| `prompt` | Detect direct and indirect prompt injection. |
| `tool_sanity` | Detect poisoned or suspicious tool descriptions. |
| `context` | Detect memory/knowledge-base poisoning patterns. |
| `supply_chain` | Detect risky skills, MCP servers, and supply-chain assets. |
| `command` | Block dangerous shell commands and command injection patterns. |
| `filesystem` | Enforce workspace/path safety and system path protections. |
| `network` | Warn/block suspicious domains, SSRF-like targets, and risky network access. |
| `exfil` | Detect possible data exfiltration. |
| `resource` | Detect resource abuse patterns. |
| `tool_policy` | Enforce configured tool allow/deny policy. |
| `credential` | Detect secrets and credentials in outputs or tool data. |
| `audit` | Record audit-oriented warning signals. |
| `output` | Review final output for sensitive or risky content. |
| `reasoning` | Optional semantic review of model/tool reasoning signals when available. |

Rules-first guards with low false-positive risk default to `enforce`. AI-first guards default to `observe` unless you enable and tune the local SLM layer.

## Optional Local SLM

Qise works in rule-only mode by default. The SLM layer adds semantic review for cases that are hard to catch with simple rules.

Start the default local SLM setup:

```bash
qise slm start
qise slm status
```

By default, Qise uses local Ollama at `http://localhost:11434/v1` with `qwen3:4b`. On first run it can try to install Ollama and pull the model if they are missing.

Use another model:

```bash
qise slm start --model llama3.2:3b
```

Use a custom OpenAI-compatible SLM endpoint:

```bash
qise slm start --base-url http://localhost:8000/v1 --model my-security-model
```

Disable the Qise SLM config:

```bash
qise slm stop
```

Keep the model server running while disabling Qise's SLM config:

```bash
qise slm stop --keep-server
```

If Qise proxy/protection was already running, restart protection after changing SLM state:

```bash
qise stop
qise protect codex
```

## Runtime Observer

The Runtime Observer is a lightweight user-space wrapper. It records the command you ran, process evidence, stdout/stderr summaries, working directory file changes, best-effort network endpoints, and a `correlation_id` that can later connect runtime and proxy evidence.

Example:

```bash
qise run --agent codex -- codex
qise events --stage runtime --limit 10
```

With a working directory:

```bash
qise run --agent codex --cwd /path/to/project -- codex
```

This is not kernel-level auditing. It is designed to give useful local evidence with low setup cost.

## Desktop App

The desktop app is a Tauri 2 + React + TypeScript interface over the same Qise CLI.

It includes pages for:

- Home status and detected agents.
- Agent Shield: protect, restore, and stop Qise services.
- Preflight Scan: scan all agents, one agent, a skill path, an MCP config, or an agent config.
- Security Events: inspect recent local events.
- Protection Rules: view and adjust guard modes while the bridge is running.
- Local SLM: start, stop, and check the optional model layer.
- System Doctor: run readiness diagnostics visually.
- Runtime Observer: build `qise run` commands and inspect runtime events.
- Backup & Restore: review backup location and restore changed configs.
- Integrations: load adapter snippets for Nanobot, Hermes, NexAU, LangGraph, and OpenAI Agents SDK.
- Settings and Advanced Lab: edit config and manually run guard/context checks.

Run the desktop app in development mode:

```bash
pip install -e ".[dev,proxy]"
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri dev
```

What each command does:

| Command | Why you run it |
| --- | --- |
| `pip install -e ".[dev,proxy]"` | Makes the Python `qise` CLI and development/test dependencies available to the desktop shell. |
| `npm --prefix src-ui install` | Installs React, Vite, TypeScript, Tailwind, and Tauri CLI frontend dependencies. |
| `src-ui/node_modules/.bin/tauri dev` | Starts the Tauri desktop shell; the configured `beforeDevCommand` starts the Vite UI server. |

Build a packaged desktop app from source:

```bash
pip install -e ".[dev,proxy]"
python -m pip install pyinstaller
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri build
```

The Tauri build runs `scripts/build-desktop-runtime.sh`, which bundles the Python Qise runtime into `src-tauri/resources/bin/qise`, then builds the React frontend and desktop package.

If you already have a standalone Qise binary, you can point the desktop app at it with:

```bash
export QISE_BINARY=/path/to/qise
```

## SDK And Framework Adapters

Qise can also be used inside agent frameworks. Print integration snippets with:

```bash
qise adapters
qise adapters langgraph
qise adapters openai-agents
qise adapters nanobot
qise adapters hermes
qise adapters nexau
```

Use adapters when you are building an agent and want in-process checks around tools, inputs, outputs, or framework hooks. Use proxy mode when you want zero-code protection for an existing OpenAI-compatible agent or Claude Code.

## Configuration

Qise can run with defaults, but you can create a config file:

```bash
qise init
```

This creates `shield.yaml` in the current directory. You can use it to configure proxy settings, model endpoints, data paths, logging, and guard modes.

Common environment variables:

| Variable | Purpose |
| --- | --- |
| `QISE_HOME` | Override Qise state directory. Defaults to `~/.qise`. |
| `QISE_AGENT_HOME` | Test/demo override for agent home/config lookup. |
| `QISE_PROXY_UPSTREAM_URL` | Upstream model API base URL for proxy mode. |
| `QISE_PROXY_UPSTREAM_API_KEY` | Upstream model API key passed to Qise proxy. |
| `OPENAI_API_BASE` | Fallback upstream base URL. |
| `OPENAI_API_KEY` | Common provider API key env used by agents and Qise. |
| `ANTHROPIC_BASE_URL` | Anthropic upstream base URL used by Claude Code or native Anthropic clients. |
| `ANTHROPIC_API_KEY` | Anthropic API key. Qise forwards it as `X-Api-Key` for `/v1/messages`. |
| `ANTHROPIC_AUTH_TOKEN` | Anthropic auth token. Qise forwards it as `Authorization: Bearer ...` for `/v1/messages`. |
| `QISE_SLM_BASE_URL` | Override SLM endpoint. |
| `QISE_SLM_MODEL` | Override SLM model name. |
| `QISE_BINARY` | Desktop app override for the Qise executable. |

## Local Files Qise Creates

By default:

```text
~/.qise/state.json       # current services, protected agents, SLM state
~/.qise/events.jsonl     # local security events
~/.qise/backups/         # agent config backups before patching
~/.qise/logs/            # managed proxy/bridge stdout and stderr logs
```

Useful inspection commands:

```bash
qise status
qise events --limit 20
ls ~/.qise/backups
```

## Troubleshooting

`qise doctor` says "Proxy upstream is not configured yet."

This is normal before you protect a real agent. Qise needs an upstream model API only when it is going to forward traffic. Use:

```bash
qise protect codex --base-url https://api.openai.com/v1
```

`qise protect codex` cannot infer the provider.

Pass the upstream explicitly:

```bash
qise protect codex --base-url https://api.openai.com/v1
```

`qise protect claude-code` cannot infer the Anthropic upstream.

Pass it explicitly:

```bash
qise protect claude-code --base-url https://api.anthropic.com
```

Qise patched an agent and you want to undo it.

```bash
qise restore all
qise stop
```

The desktop app cannot find Qise.

Make sure the CLI works in the same shell:

```bash
qise version
```

If needed, set:

```bash
export QISE_BINARY=/path/to/qise
```

A scan command exits non-zero.

That usually means Qise found a blocking issue. Re-run with `--json` for structured details or read the latest event:

```bash
qise events --limit 5
```

## Current Limitations

- Source install is the main supported install path until package publishing is finished.
- Proxy mode currently targets OpenAI-compatible chat/completions traffic and Anthropic Messages `/v1/messages` traffic.
- Runtime Observer is a user-space wrapper, not OS/kernel-level auditing.
- Desktop app packaging is source-build oriented in the current MVP.
- Local SLM quality and latency depend on the model and server you choose.

## Learn More

- [Install](./docs/install.md)
- [Quickstart](./docs/quickstart.md)
- [Architecture](./docs/architecture.md)
- [Guards](./docs/guards.md)
- [Codex integration](./docs/codex.md)
- [OpenClaw integration](./docs/openclaw.md)
- [Claude Code integration](./docs/claude-code.md)
- [Preflight scan](./docs/preflight-scan.md)
- [Events](./docs/events.md)
- [Runtime Observer](./docs/runtime-observer.md)
- [Troubleshooting](./docs/troubleshooting.md)
- [Privacy](./docs/privacy.md)
