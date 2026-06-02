<div align="center">

# Qise

**Local-first security for AI coding agents.**

Qise helps you use agents such as Codex, OpenClaw, Claude Code, and custom agents with a local safety layer. It can scan risky integrations, route model traffic through a guard proxy, block dangerous actions, and show a readable local event trail.

[中文](./README_CN.md) | [Quickstart](./docs/quickstart.md) | [Install](./docs/install.md) | [Architecture](./docs/architecture.md) | [Privacy](./docs/privacy.md)

</div>

> [!IMPORTANT]
> This project is still under active development and may contain bugs. Contributions via Issues and PRs are welcome.
---

## Start Here

Qise has three entry points:

| You are | Start with | Why |
| --- | --- | --- |
| A regular agent user | Desktop App | Detect agents, protect them, scan configs, and read events without memorizing commands. |
| A terminal/CLI user | `qise` CLI | Run scans, protect agents, inspect events, and automate checks from scripts. |
| An agent developer | SDK / adapters | Add Qise checks inside LangGraph, OpenAI Agents SDK, Nanobot, Hermes, or NexAU. |

The desktop app and CLI use the same Python Qise product engine. The UI is not a separate implementation, so protection behavior stays aligned across both interfaces.

## What Qise Does

AI coding agents can read files, run shell commands, call MCP servers, install skills, use memories, and send data to model APIs. That power is useful, but it creates a new local security boundary: poisoned tool descriptions, malicious skills, prompt injection, unsafe commands, and accidental secret leaks can become real machine-level risk.

Qise runs on your machine beside the agent you already use. It is not a model provider and it does not replace your agent.

In the common proxy mode, the flow is:

```text
AI Agent -> Qise local proxy -> your existing model API
```

Qise can:

- Detect supported agents such as Codex, OpenClaw, and Claude Code.
- Back up an agent config before changing it.
- Route the agent through a local guard proxy.
- Check tool calls before they reach your system.
- Block dangerous commands such as destructive shell operations.
- Warn about suspicious file, network, credential, and exfiltration behavior.
- Scan skills, MCP configs, and agent configs before you trust them.
- Add local security context to agent/model requests.
- Record local JSONL security events with risk, evidence, verdict, and recommendation.
- Optionally use a local small language model through Ollama or another OpenAI-compatible endpoint as a second semantic review layer.

Qise is local-first. Product state, backups, and events are stored under `~/.qise/` by default. Event records store compact evidence snippets, not full model traffic.

## Current Status

Qise is currently an alpha/MVP project. macOS desktop packaging can be built from source. PyPI and signed release distribution are still release-process work.

| Area | What works now | Status |
| --- | --- | --- |
| Desktop app | Tauri 2 + React UI over the same Qise CLI/product engine | Source-build MVP |
| CLI | `doctor`, `status`, `agents`, `scan`, `check`, `events`, `protect`, `restore`, `stop`, `slm`, `run` | Active MVP |
| Proxy protection | OpenAI-compatible `/v1/chat/completions` and Anthropic `/v1/messages` local proxy | Active MVP |
| Claude Code | Native Anthropic Messages proxy with request/response parsing, security-context injection, and streaming `tool_use` checks | Active MVP |
| Preflight scan | Skill, MCP config, agent config, and detected agent asset scanning | Active MVP |
| Guard engine | 14 guard categories across ingress, egress, and output pipelines | Active MVP |
| Event log | Local JSONL events with risk, evidence, verdict, recommendation, and correlation IDs | Active MVP |
| Local SLM | Optional semantic review layer through Ollama or custom OpenAI-compatible endpoint | Active MVP |
| Runtime Observer | User-space wrapper for process, stdout/stderr, file diff, and best-effort network evidence | MVP |
| SDK/adapters | Framework adapters for Nanobot, Hermes, NexAU, LangGraph, and OpenAI Agents SDK | Developer MVP |

## Install The Desktop App

The desktop app is the easiest way to try Qise as a product. It gives you pages for protection status, agent detection, one-click protection, preflight scanning, event logs, guard rules, local SLM setup, backups, diagnostics, and SDK snippets.

### Option A: Install A Prebuilt macOS DMG

When a release DMG is attached to GitHub Releases:

1. Download the macOS DMG, for example `Qise_0.2.0_aarch64.dmg`.
2. Double-click the DMG.
3. Drag `Qise.app` into `Applications`.
4. Open `Qise.app`.

If macOS blocks the first launch because the build is not notarized yet, right-click `Qise.app`, choose `Open`, then confirm. You can also allow it from `System Settings -> Privacy & Security`.

### Option B: Build The macOS App From Source

Run these commands from a terminal:

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,proxy]"
python -m pip install pyinstaller
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri build
```

What each command does:

| Command | Why you run it |
| --- | --- |
| `git clone ...` | Downloads the Qise source code. |
| `cd qise` | Moves into the project directory. |
| `python3.11 -m venv .venv` | Creates an isolated Python environment. |
| `source .venv/bin/activate` | Makes `python` and `pip` use that environment. |
| `pip install -e ".[dev,proxy]"` | Installs the Qise CLI/product engine and development/proxy dependencies. |
| `python -m pip install pyinstaller` | Installs the tool used to bundle the Python Qise runtime into the desktop app. |
| `npm --prefix src-ui install` | Installs React, Vite, TypeScript, and Tauri frontend dependencies. |
| `src-ui/node_modules/.bin/tauri build` | Builds the bundled Qise runtime, React UI, `.app`, and `.dmg`. |

After a successful build, the important files are:

```text
src-tauri/target/release/bundle/macos/Qise.app
src-tauri/target/release/bundle/dmg/Qise_0.2.0_aarch64.dmg
```

The exact DMG suffix can vary by version and CPU architecture. On Apple Silicon, it is commonly `aarch64`.

To install the locally built app:

1. Open `src-tauri/target/release/bundle/dmg/Qise_0.2.0_aarch64.dmg`.
2. Drag `Qise.app` into `Applications`.
3. Open `Qise.app`.

The build also creates an internal CLI runtime at:

```text
src-tauri/resources/bin/qise
```

That binary is a generated build artifact and should not be committed.

### Run The Desktop App In Development Mode

Use this when you are editing the UI or testing quickly:

```bash
source .venv/bin/activate
npm --prefix src-ui install
src-ui/node_modules/.bin/tauri dev
```

## First Use In The Desktop App

1. Open `Qise.app`.
2. Click `Detect Agents` on the home page.
3. Go to `Agent Shield`.
4. Choose an agent such as Codex, OpenClaw, or Claude Code.
5. Check the upstream model API URL.
6. Click `Protect`.
7. Use your agent normally.
8. Return to Qise and open `Security Events` to see warnings and blocks.

For Claude Code, keep your Anthropic key available in the environment:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

The Claude Code upstream is normally:

```text
https://api.anthropic.com
```

To undo Qise changes from the desktop app, use `Backup & Restore` or `Agent Shield`. From the CLI, use:

```bash
qise restore all
qise stop
```

## Install The CLI From Source

If you prefer the terminal, install Qise as a Python package:

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
```

What each command does:

| Command | Why you run it |
| --- | --- |
| `git clone ...` | Downloads the repository. |
| `cd qise` | Enters the project directory. |
| `python3.11 -m venv .venv` | Creates a clean Python environment. |
| `source .venv/bin/activate` | Activates that environment. |
| `pip install -e ".[proxy]"` | Installs Qise in editable mode with proxy runtime dependencies. |
| `qise doctor` | Checks Python, Qise import, config, local ports, event log, optional SLM, and detected agents. |

For development and tests:

```bash
pip install -e ".[dev,proxy]"
```

## First Safe CLI Demo

This demo uses temporary directories and does not touch your real Codex config:

```bash
bash ./scripts/demo_mvp.sh
```

The demo runs readiness checks, protects a fake Codex config, blocks a dangerous command, prints the event, and restores the temporary config.

You can also run the preflight scan demo:

```bash
bash ./scripts/demo_scan.sh
```

It scans a safe skill, a dangerous skill, and a dangerous MCP config, then shows the events Qise recorded.

## Manual CLI Walkthrough

After installation, this sequence gives you a quick product loop:

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

The `|| true` suffix is used because a block is represented as a non-zero exit code. That is expected for dangerous test inputs.

For machine-readable output:

```bash
qise status --json
qise events --limit 10 --json
qise scan mcp examples/mcp-dangerous.json --json || true
```

## Protect A Real Agent With The CLI

Protection means Qise backs up your agent config, patches the agent's model base URL to point at the local Qise proxy, starts managed Qise services, and records the backup path so you can restore later.

Before protecting a real agent, make sure:

- Your agent already works without Qise.
- Your model provider API key is still available in the environment your agent uses.
- You know the upstream model API base URL if Qise cannot infer it from the agent config.

Protect Codex:

```bash
qise protect codex
qise status
qise events --limit 10
```

If Qise cannot infer the upstream provider:

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

What the Claude Code command does:

| Command | What it does |
| --- | --- |
| `export ANTHROPIC_API_KEY=...` | Keeps your Anthropic key available to Claude Code and the Qise-managed proxy process. |
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

If Qise proxy/protection was already running, restart protection after changing SLM state:

```bash
qise stop
qise protect codex
```

## SDK And Framework Adapters

Qise can also be used inside agent frameworks. This is intended for developers building agents or tools.

Print integration snippets:

```bash
qise adapters
qise adapters langgraph
qise adapters openai-agents
qise adapters nanobot
qise adapters hermes
qise adapters nexau
```

Example LangGraph snippet:

```python
from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]
```

Example OpenAI Agents SDK snippet:

```python
from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)
agent = Agent(
    name="my-agent",
    guardrails=[guardrails.input_guardrail, guardrails.output_guardrail],
)
```

Use adapters when you are building an agent and want in-process checks around tools, inputs, outputs, or framework hooks. Use proxy mode when you want zero-code protection for an existing OpenAI-compatible agent or Claude Code.

## Integration Modes

| Mode | Code required | Best for |
| --- | --- | --- |
| Desktop app | 0 lines | Regular users who want a visual control panel. |
| Proxy mode | 0 lines | Existing agents that can point model traffic to a local base URL. |
| MCP mode | 0 lines | Agents that can call Qise as an MCP server. |
| SDK mode | 1-5 lines | Developers building agent frameworks or custom tools. |

## Project Shape

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

## Configuration

Qise can run with defaults, but you can create a config file:

```bash
qise init
```

This creates `shield.yaml` in the current directory. Use it to configure proxy settings, model endpoints, data paths, logging, and guard modes.

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

- Source install and source-built desktop packages are the main supported paths until package publishing and signed releases are finished.
- Proxy mode currently targets OpenAI-compatible chat/completions traffic and Anthropic Messages `/v1/messages` traffic.
- Runtime Observer is a user-space wrapper, not OS/kernel-level auditing.
- Local SLM quality and latency depend on the model and server you choose.
- This README focuses on macOS desktop packaging for now. Windows packaging is not documented here yet.

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

## License

[CC BY-NC-SA 4.0](./LICENSE) - free for personal, academic, and non-commercial use. Commercial use requires separate permission.
