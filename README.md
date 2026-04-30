<div align="center">

# 🧀 Qise

**AI-First Runtime Security Framework for AI Agents**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-green.svg)](LICENSE)
[![Tests: 461+ passed](https://img.shields.io/badge/Tests-461%2B%20passed-brightgreen.svg)](tests/)
[![Guards: 14](https://img.shields.io/badge/Guards-14-orange.svg)](src/qise/guards/)
[![Adapters: 5](https://img.shields.io/badge/Adapters-5-purple.svg)](src/qise/adapters/)
[![Desktop: Tauri 2](https://img.shields.io/badge/Desktop-Tauri%202-blue.svg)](src-tauri/)

[English](#overview) | [中文](./README_CN.md)

</div>

---

## Overview

Qise (pronounced "Cheese" 🧀) is an open-source runtime security framework that protects AI agents from **both directions**:

- **World → Agent**: Stops prompt injection, tool poisoning, memory/KB tampering, and supply chain attacks
- **Agent → World**: Stops dangerous commands, path traversal, SSRF, data exfiltration, and policy violations

Unlike rule-only solutions that are easily bypassed, Qise uses **layered AI models** (SLM fast-screen + LLM deep analysis) to understand attack *intent*, with deterministic rules as fast-path and fallback — **never fail-open**.

## System Architecture

```
Agent (Claude Code / Codex / Gemini CLI / Custom)
    │
    │ API Request (OpenAI-compatible format)
    ▼
┌─────────────────────────────────────────────────────────┐
│                Tauri 2 Desktop App                       │
│  ┌───────────────────────────────────────────────────┐  │
│  │  System Tray │ Guard Dashboard │ Config Editor    │  │
│  │  Agent Panel │ Event Log (WS)  │ Stats Bar        │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  Rust Proxy (axum, port 8822)                           │
│  • Request/Response interception                        │
│  • SSE streaming passthrough                            │
│  • Guard pipeline integration                           │
│  • Proxy Takeover (env + config file)                   │
├─────────────────────────────────────────────────────────┤
│  Python Bridge (aiohttp, port 8823)                     │
│  • Guard Pipeline execution                             │
│  • SLM/LLM inference (httpx)                            │
│  • WebSocket event push (/v1/bridge/events/stream)      │
│  • 7 HTTP endpoints + 1 WS endpoint                     │
├─────────────────────────────────────────────────────────┤
│  Guard Pipeline (14 Guards)                             │
│  Ingress: Prompt → ToolSanity → Context → SupplyChain  │
│  Egress:  Command → FS → Network → Exfil → Resource    │
│  Output:  Credential → Audit → Output                   │
│  Soft:    SecurityContextProvider + ReasoningGuard       │
├─────────────────────────────────────────────────────────┤
│  Model Layer                                            │
│  SLM: Ollama qwen3:4b (local, <2s)                     │
│  LLM: Cloud API (Claude/GPT/Qwen, <5s)                  │
│  Rules: Deterministic fallback (<1ms)                    │
└─────────────────────────────────────────────────────────┘
    │
    │ Forwarded Request
    ▼
  Upstream LLM API
```

---

## Quick Start

### 1. Install Python Engine

```bash
# Clone and install
git clone https://github.com/morinop/qise.git
cd qise
pip install -e ".[dev]"
```

### 2. One-Command Setup

```bash
# Generate default config
qise init

# Check a tool call
qise check bash '{"command": "rm -rf /"}'
# → {"verdict": "block", "blocked_by": "command", ...}

qise check bash '{"command": "ls"}'
# → {"verdict": "pass", "blocked_by": null, "warnings": []}

# List all guards and their modes
qise guards
```

### 3. Setup Local SLM (Recommended)

Qise works out-of-the-box with rules only, but AI-first guards need an SLM. Local Ollama gives <2s latency:

```bash
# One-click: install Ollama + pull qwen3:4b (~2.4GB)
chmod +x scripts/setup_slm.sh
./scripts/setup_slm.sh
```

Or manually:
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:4b
ollama serve
```

Then configure `shield.yaml`:
```yaml
models:
  slm:
    base_url: "http://localhost:11434/v1"
    model: "qwen3:4b"
    timeout_ms: 5000
```

### 4. Zero-Code: Proxy Mode

Start a local HTTP proxy that intercepts all Agent↔LLM traffic:

```bash
# Start proxy server
qise proxy start --port 8822 --upstream https://api.openai.com

# Point your agent at the proxy
export OPENAI_API_BASE="http://localhost:8822/v1"
```

The proxy intercepts requests/responses in real-time, running all 14 guards on tool calls, injection attempts, and output leaks — with **SSE streaming support** for zero-latency text passthrough.

### 5. Desktop App (One-Click Security)

The Qise desktop app provides a one-click security toggle with real-time monitoring:

```bash
# Prerequisites: Node.js + Rust
cd src-tauri && cargo tauri dev
```

**Features:**
- **System Tray**: One-click protection toggle, status indicator, menu text auto-switches
- **Guard Dashboard**: Real-time guard events, mode switching (observe/enforce/off)
- **Config Editor**: Visual shield.yaml editing (SLM, LLM, Guards, Integration)
- **Agent Panel**: Detect installed agents, one-click proxy takeover with crash recovery
- **Event Log**: WebSocket real-time push, filter by All/Blocked/Warnings
- **Stats Bar**: Blocked/warning counts, SLM status (local/cloud/unavailable), latency

**Proxy Takeover**: Click "Take Over" to redirect your agent's API endpoint to the Qise proxy. Original config is backed up and auto-restored on exit or crash.

| Agent | Method | Redirect Target |
|-------|--------|-----------------|
| Generic OpenAI | `OPENAI_API_BASE` env var | `http://localhost:8822/v1` |
| Claude Code | `ANTHROPIC_BASE_URL` env var + `~/.claude/settings.json` | `http://localhost:8822/v1` |

### 6. Zero-Code: MCP Mode

Add to your agent's MCP configuration:

```json
{
  "mcpServers": {
    "qise": {
      "command": "python",
      "args": ["-m", "qise.mcp_server"]
    }
  }
}
```

### 7. SDK Mode: Framework Adapters

**Nanobot:**
```python
from qise import Shield
from qise.adapters.nanobot import QiseNanobotHook

shield = Shield.from_config()
hook = QiseNanobotHook(shield)
loop = AgentLoop(hooks=[hook])
```

**LangGraph:**
```python
from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper

shield = Shield.from_config()
wrapper = QiseLangGraphWrapper(shield)
safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]
```

**NexAU:**
```python
from qise import Shield
from qise.adapters.nexau import QiseNexauMiddleware

shield = Shield.from_config()
middleware = QiseNexauMiddleware(shield)
agent = NexAUAgent(middlewares=[middleware])
```

**OpenAI Agents SDK:**
```python
from qise import Shield
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

shield = Shield.from_config()
guardrails = QiseOpenAIAgentsGuardrails(shield)
agent = Agent(guardrails=[guardrails.input_guardrail, guardrails.output_guardrail])
```

**Hermes:**
```python
from qise import Shield
from qise.adapters.hermes import QiseHermesPlugin

shield = Shield.from_config()
plugin = QiseHermesPlugin(shield)
plugin.register(ctx)
```

---

## Why Qise

| Problem | Qise's Approach |
|---------|----------------|
| Keyword rules easily bypassed | AI understands attack semantics, not just pattern matching |
| Single model bottleneck | Layered models: SLM <50ms fast-screen + LLM deep analysis |
| Fail-open on model errors | Rule fallback — **never fail-open** |
| No exfiltration detection | ExfilGuard: AI-first data exfiltration detection |
| No tool poisoning detection | ToolSanityGuard: hash baseline + AI semantic analysis |
| Static safety instructions | Dynamic SecurityContextProvider + Guard enforcement |
| Requires code changes | Proxy mode / MCP mode: zero-code integration |
| Cloud SLM latency 14-30s | Local Ollama qwen3:4b: <2s per call |

## Three-Layer Decision Flow

Every guard uses the same decision flow — rules first for speed, AI for semantics, rules last for safety:

```
  ┌──────────────────┐
  │ Rule Fast-Path   │  <1ms — deterministic BLOCK or PASS
  │ (regex, hash,    │  e.g., "rm -rf /" → BLOCK
  │  patterns)       │  For AI-first guards, only BLOCK short-circuits
  └────────┬─────────┘  (rule PASS flows to SLM for final say)
           │ uncertain or PASS (AI-first guards)
           ▼
  ┌──────────────────┐
  │ SLM Fast-Screen  │  <2s (local Ollama) — semantic classification
  │ (≤4B model)      │  e.g., obfuscated command → BLOCK
  └────────┬─────────┘  e.g., paraphrased injection → ESCALATE
           │ SLM can override low-confidence rule WARNs (<0.65)
           │ but not high-confidence ones (≥0.65)
           ▼
  ┌──────────────────┐
  │ LLM Deep Analysis│  <2s — full trajectory reasoning
  │ (8B-70B model)   │  e.g., multi-turn attack chain → BLOCK
  └────────┬─────────┘
           │ model unavailable
           ▼
  ┌──────────────────┐
  │ Rule Fallback    │  <1ms — conservative defaults
  │ (never fail-open)│  e.g., WARN on uncertain + network tool
  └──────────────────┘
```

## Defense in Depth

```
  Layer 0: SecurityContextProvider  →  Agent follows voluntarily (~80%)
  Layer 1: ReasoningGuard          →  Chain-of-thought monitoring + threshold adjustment
  Layer 2: Guard Pipeline (14)     →  Rule → SLM → LLM → Rule fallback
  Layer 3: OutputGuard + CredentialGuard  →  Data leak detection
```

## 14 Guards at a Glance

### Ingress Pipeline (World → Agent)

| Guard | Strategy | Detects |
|-------|----------|---------|
| **PromptGuard** | AI-first (80/20) | Indirect injection, multi-turn attacks, context poisoning |
| **ToolSanityGuard** | AI-first (80/20) | Tool description poisoning, rug pulls, name shadowing |
| **ContextGuard** | AI+hash (70/30) | Memory/KB poisoning, data tampering, hash integrity |
| **SupplyChainGuard** | AI+rules (60/40) | Malicious Skills, MCP tampering, source verification |

### Egress Pipeline (Agent → World)

| Guard | Strategy | Detects |
|-------|----------|---------|
| **ReasoningGuard** \* | AI-only (100/0) | Manipulation traces in chain-of-thought, threshold adjustment |
| **CommandGuard** | Rules+AI (70/30) | Shell injection, dangerous commands, privilege escalation |
| **FilesystemGuard** | Rules (90/10) | Path traversal, workspace violations, system dir access |
| **NetworkGuard** | Rules (90/10) | SSRF, forbidden domains, internal network scanning |
| **ExfilGuard** | AI-first (80/20) | Data exfiltration, covert channels, DNS exfil |
| **ResourceGuard** | Rules+AI (60/40) | Infinite loops, budget overruns, circuit breaker |
| **ToolPolicyGuard** | Rules (100/0) | Unauthorized tool access, deny/approval/owner-only |

### Output Pipeline (Audit)

| Guard | Strategy | Detects |
|-------|----------|---------|
| **CredentialGuard** | Rules (100/0) | API keys, secrets, tokens in output |
| **AuditGuard** | AI+rules (50/50) | Attack chain reconstruction, session risk scoring |
| **OutputGuard** | AI+rules (70/30) | PII exposure, KB content leaks, credential leaks |

> **\*** ReasoningGuard is cross-cutting — detects manipulation in chain-of-thought and adjusts thresholds of other guards.

## 5 Framework Adapters

| Framework | Ingress | Egress | Output | SecContext |
|-----------|---------|--------|--------|------------|
| **Nanobot** | ✅ | ✅ | ✅ | ✅ |
| **Hermes** | ✅ | ✅ | ✅ | — |
| **NexAU** | ✅ | ✅ | ✅ | ✅ |
| **LangGraph** | — | ✅ | — | ✅ |
| **OpenAI Agents** | ✅ | ✅ | ✅ | — |

All adapters use **IngressCheckMixin + EgressCheckMixin** — no monkey-patching, only official Hook/Plugin/Middleware APIs.

## Configuration (shield.yaml)

```yaml
version: "1.0"

integration:
  mode: proxy          # proxy | mcp | sdk
  proxy:
    port: 8822
    auto_takeover: true
    crash_recovery: true

models:
  slm:
    base_url: "http://localhost:11434/v1"   # Ollama
    model: "qwen3:4b"
    timeout_ms: 5000
  llm:
    base_url: "https://api.anthropic.com"
    model: "claude-sonnet-4-5"
    timeout_ms: 5000

guards:
  enabled: [prompt, command, credential, reasoning, filesystem, network,
            exfil, resource, audit, tool_sanity, context, output, tool_policy, supply_chain]
  config:
    prompt:
      mode: observe           # observe | enforce | off
      slm_confidence_threshold: 0.7
      skip_slm_on_rule_pass: false
    command:
      mode: enforce
    exfil:
      mode: observe
      skip_slm_on_rule_pass: true
      slm_override_rule_warn_threshold: 0.8
```

Environment variable overrides: `QISE_SLM_BASE_URL`, `QISE_SLM_MODEL`, `QISE_SLM_API_KEY`, `QISE_LLM_BASE_URL`, `QISE_PROXY_PORT`, `QISE_MODE`.

## Performance

| Operation | Target | Measured (p95) |
|-----------|--------|----------------|
| Rule fast-path (single guard) | <1ms | ~0.02ms |
| Full egress pipeline (6 guards) | <10ms | ~0.02ms |
| Local SLM (Ollama qwen3:4b) | <2s | ~500ms-2s (M1+) |
| Full pipeline + local SLM | <3s | ~1-2s |

## Scripts

| Script | Description |
|--------|-------------|
| `scripts/setup_slm.sh` | Install Ollama + pull qwen3:4b (one-click local SLM) |
| `scripts/benchmark_slm.py` | Compare local Ollama vs cloud SLM latency |
| `scripts/e2e_tauri_test.py` | End-to-end verification: Proxy → Bridge → Guard → API |

## Development

```bash
pip install -e ".[dev]"     # Install with dev dependencies
pytest tests/ -v             # Run 461+ tests
ruff check .                 # Lint
ruff format .                # Format
mypy src/qise               # Type check
cd src-tauri && cargo tauri dev    # Run desktop app
cd src-tauri && cargo tauri build  # Build desktop app
```

## Evaluation Results

R12-tuned evaluation (SLM + rules pipeline vs rules-only baseline):

| Metric | Rules-Only | SLM + Rules | Delta |
|--------|-----------|-------------|-------|
| **Precision** | 0.643 | **1.000** | +0.357 |
| **Recall** | 0.973 | **1.000** | +0.027 |
| **F1** | 0.774 | **1.000** | +0.226 |
| **FPR** | 0.400 | **0.000** | +0.400 (lower=better) |

## Architecture

```
qise/
├── src/qise/
│   ├── core/              # GuardContext, AIGuardBase, Pipeline, Shield, Config
│   ├── guards/            # 14 Guard implementations
│   ├── models/            # ModelRouter (httpx-based OpenAI-compatible client)
│   ├── data/              # ThreatPatternLoader + BaselineManager + SQLite
│   ├── providers/         # SecurityContextProvider (DSL template rendering)
│   ├── adapters/          # 5 Framework adapters
│   ├── proxy/             # HTTP proxy server (aiohttp + SSE)
│   ├── bridge/            # Python Bridge (7 HTTP + 1 WS endpoint)
│   └── mcp_server.py      # MCP Server (4 security check tools)
├── src-tauri/             # Desktop App (Tauri 2 + React)
│   ├── src/               #   Rust backend (proxy, bridge, takeover, 12 IPC commands)
│   └── icons/             #   App icons
├── src-ui/                # React frontend (Raycast-style dark UI)
│   └── src/components/    #   StatusIndicator, ProxyToggle, GuardList, EventLog,
│                          #   AgentPanel, ConfigPanel
├── scripts/               # setup_slm.sh, benchmark_slm.py, e2e_tauri_test.py
├── data/                  # threat_patterns/, security_contexts/, prompts/
├── tests/                 # 461+ tests
├── eval/                  # Evaluation datasets and results
└── docs/                  # Architecture, Guards, Threat Model, Integration
```

## CLI Reference

```bash
qise check bash '{"command": "rm -rf /"}'  # Single security check
qise serve                                  # Start MCP Server
qise proxy start --port 8822                # Start Rust HTTP proxy
qise bridge start --port 8823               # Start Python Bridge
qise init                                   # Generate shield.yaml
qise guards                                 # List registered guards
qise adapters                               # List framework adapters
qise context bash                           # Get security context
qise version                                # Print version
```

## Integration Modes

| Mode | Code Required | Defense Depth | Best For |
|------|--------------|---------------|----------|
| **Proxy Mode** | 0 lines | Full (4 layers) | Desktop users, non-developers |
| **MCP Mode** | 0 lines | Hard defense (14 guards) | MCP ecosystem users |
| **SDK Mode** | 1-5 lines | Full (4 layers) + lowest latency | Agent developers |

## Status

| Component | Status |
|-----------|--------|
| Core engine (AIGuardBase, Pipeline, Shield) | ✅ Complete |
| 14 Guards (Ingress + Egress + Output) | ✅ Complete |
| ModelRouter (httpx-based SLM/LLM client) | ✅ Complete |
| Ollama SLM integration (qwen3:4b, <2s) | ✅ Complete |
| Rust Proxy (axum + hyper + rustls, SSE streaming) | ✅ Complete |
| Python Bridge (aiohttp, 7 HTTP + 1 WS endpoint) | ✅ Complete |
| Desktop App (Tauri 2, System Tray, Config Editor) | ✅ Complete |
| Proxy Takeover (env + config file + crash recovery) | ✅ Complete |
| Real-time Frontend (GuardList, EventLog, AgentPanel, ConfigPanel) | ✅ Complete |
| 5 Framework Adapters (Nanobot, Hermes, NexAU, LangGraph, OpenAI Agents) | ✅ Complete |
| MCP Server (4 security check tools) | ✅ Complete |
| SecurityContextProvider (DSL template rendering) | ✅ Complete |
| BaselineManager (SHA-256 hash + SQLite) | ✅ Complete |
| 461+ unit + integration + performance tests | ✅ Complete |
| OpenAI Agents SDK E2E Test (10/10 passed) | ✅ Complete |

## License

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) — Free for personal, academic, and non-commercial use. Commercial use requires separate permission.
