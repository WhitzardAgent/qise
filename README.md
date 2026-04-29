<div align="center">

# 🧀 Qise

**AI-First Runtime Security Framework for AI Agents**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-green.svg)](LICENSE)
[![Tests: 439 passed](https://img.shields.io/badge/Tests-439%20passed-brightgreen.svg)](tests/)
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

```
┌─────────────────────────────────────────────────────────────────┐
│                        Qise Security Framework                   │
│                                                                 │
│   ┌─── Soft Defense ──────────────────────────────────────────┐ │
│   │  SecurityContextProvider  →  Scene-aware rules injection  │ │
│   │  ReasoningGuard          →  Chain-of-thought monitoring   │ │
│   └───────────────────────────────────────────────────────────┘ │
│                           ↓ still executes                      │
│   ┌─── Hard Defense (14 Guards) ─────────────────────────────┐ │
│   │                                                           │ │
│   │  Ingress (World → Agent)                                  │ │
│   │  ┌────────┐ ┌────────────┐ ┌─────────┐ ┌──────────────┐ │ │
│   │  │ Prompt │ │ ToolSanity │ │ Context │ │ SupplyChain  │ │ │
│   │  │ Guard  │ │   Guard    │ │  Guard  │ │    Guard     │ │ │
│   │  └────────┘ └────────────┘ └─────────┘ └──────────────┘ │ │
│   │                                                           │ │
│   │  Egress (Agent → World)                                   │ │
│   │  ┌──────────┐┌─────────┐┌──────────┐┌────────┐┌──────┐  │ │
│   │  │Reasoning ││Command  ││Filesystem││Network ││Exfil │  │ │
│   │  │  Guard*  ││ Guard   ││  Guard   ││ Guard  ││Guard │  │ │
│   │  └──────────┘└─────────┘└──────────┘└────────┘└──────┘  │ │
│   │  ┌──────┐ ┌──────┐                                    │ │
│   │  │Policy│ │Resrc │                                    │ │
│   │  │Guard │ │Guard │                                    │ │
│   │  └──────┘ └──────┘                                    │ │
│   │                                                           │ │
│   │  Output (Audit)                                           │ │
│   │  ┌──────────┐┌───────────┐ ┌──────────┐ ┌──────────┐    │ │
│   │  │Reasoning ││Credential │ │  Audit   │ │  Output  │    │ │
│   │  │  Guard*  ││   Guard   │ │  Guard   │ │  Guard   │    │ │
│   │  └──────────┘└───────────┘ └──────────┘ └──────────┘    │ │
│   └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│   ┌─── Shared Services ──────────────────────────────────────┐ │
│   │  ModelRouter (SLM <50ms + LLM <2s) │ ThreatPatternLoader │ │
│   │  BaselineManager (SHA-256) │ SessionTracker │ EventLogger │ │
│   └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

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
  │ SLM Fast-Screen  │  <50ms — semantic classification
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

**Key principle**: SLM can ESCALATE a rule verdict but selectively DOWNGRADE it. Trust boundary isolation WARNs (low confidence, <0.65) are precautions SLM can override with content analysis. Hardcoded pattern WARNs (high confidence, ≥0.65) are findings SLM cannot downgrade.

## Defense in Depth

Four layers protect from soft guidance to hard enforcement:

```
  Layer 0: SecurityContextProvider
           ┌─────────────────────────────────────────────┐
           │ Inject scene-aware security rules into agent │
           │ Agent follows voluntarily (~80% prevention)  │
           └──────────────────────┬──────────────────────┘
                                  ↓ Agent ignores rules
  Layer 1: ReasoningGuard
           ┌─────────────────────────────────────────────┐
           │ SLM detects manipulation in chain-of-thought │
           │ Inserts safety reminders, lowers thresholds  │
           └──────────────────────┬──────────────────────┘
                                  ↓ Agent still executes
  Layer 2: Guard Pipeline (14 Guards)
           ┌─────────────────────────────────────────────┐
           │ Rule → SLM → LLM → Rule fallback            │
           │ BLOCK / WARN / APPROVE                      │
           └──────────────────────┬──────────────────────┘
                                  ↓ Action already executed
  Layer 3: OutputGuard + CredentialGuard
           ┌─────────────────────────────────────────────┐
           │ Detect data leaks, PII, credentials         │
           └─────────────────────────────────────────────┘
```

## Quick Start

### Install

```bash
pip install qise
```

### One-Command Setup

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

### Zero-Code: Proxy Mode

Start a local HTTP proxy that intercepts all Agent↔LLM traffic:

```bash
# Start proxy server (Rust, high-performance)
qise proxy start --port 8822 --upstream https://api.openai.com

# Point your agent at the proxy
export OPENAI_API_BASE="http://localhost:8822/v1"
```

The proxy intercepts requests/responses in real-time, running all 14 guards on tool calls, injection attempts, and output leaks — with **SSE streaming support** for zero-latency text passthrough.

### Desktop App (Zero-Code, One-Click)

The Qise desktop app provides a one-click security toggle with real-time monitoring:

```bash
# Build and run the desktop app
cd src-tauri && cargo tauri dev
```

**Features:**
- **System Tray**: One-click protection toggle, status indicator
- **Guard Dashboard**: Real-time guard events, mode switching (observe/enforce/off)
- **Agent Panel**: Detect installed agents, one-click proxy takeover with crash recovery
- **Stats Bar**: Blocked/warning counts, proxy/bridge port display

**Proxy Takeover**: Click "Take Over" to automatically redirect your agent's API endpoint to the Qise proxy. Original config is backed up and auto-restored on exit or crash.

| Agent | Environment Variable | Redirect Target |
|-------|---------------------|-----------------|
| Generic OpenAI | `OPENAI_API_BASE` | `http://localhost:8822/v1` |
| Claude Code | `ANTHROPIC_BASE_URL` | `http://localhost:8822/v1` |

### Zero-Code: MCP Mode

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

### SDK Mode: Framework Adapters

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

### Run Tests

```bash
pytest tests/ -v    # 439 tests
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
| **ReasoningGuard** \* | AI-only (100/0) | Manipulation traces in chain-of-thought, threshold adjustment |
| **CredentialGuard** | Rules (100/0) | API keys, secrets, tokens in output |
| **AuditGuard** | AI+rules (50/50) | Attack chain reconstruction, session risk scoring |
| **OutputGuard** | AI+rules (70/30) | PII exposure, KB content leaks, credential leaks |

> **\*** ReasoningGuard is a cross-cutting guard that appears in both Egress and Output pipelines. It detects manipulation in the agent's chain-of-thought and adjusts thresholds of other guards — it does not block independently.

## 5 Framework Adapters

| Framework | Adapter | Hook Points | Ingress | Egress | Output | SecContext |
|-----------|---------|-------------|---------|--------|--------|------------|
| **Nanobot** | QiseNanobotHook | before_execute_tools, after_iteration | ✅ | ✅ | ✅ | ✅ |
| **Hermes** | QiseHermesPlugin | pre/post_tool_call, transform_result, post_llm_call | ✅ | ✅ | ✅ | — |
| **NexAU** | QiseNexauMiddleware | before/after_agent, before/after_model, before/after_tool | ✅ | ✅ | ✅ | ✅ |
| **LangGraph** | QiseLangGraphWrapper | wrap/awrap_tool_call, pre_model_hook | — | ✅ | — | ✅ |
| **OpenAI Agents** | QiseOpenAIAgentsGuardrails | input/output_guardrail, tool_input/output_guardrail | ✅ | ✅ | ✅ | — |

All adapters use the **IngressCheckMixin + EgressCheckMixin** base classes — no monkey-patching, only official Hook/Plugin/Middleware APIs.

## Model Layer

| Tier | Model | Latency | Usage |
|------|-------|---------|-------|
| SLM fast-screen | Qwen3-4B / Phi-4-mini | <50ms | Every tool call (AI-first guards) |
| LLM deep analysis | Claude / GPT / Qwen-72B | <2s | Only when SLM escalates (~5%) |
| Rule fallback | Deterministic rules | <1ms | When models unavailable (never fail-open) |

**Stub mode**: Works out of the box without any model server — all guards degrade to rules gracefully. Rules-based guards (command, filesystem, network, credential, tool_policy) default to **enforce** mode; AI-first guards default to **observe** mode.

## Performance

Rule-only mode adds virtually zero overhead:

| Operation | Target | Measured (p95) |
|-----------|--------|----------------|
| Rule fast-path (single guard) | <1ms | ~0.02ms |
| Full egress pipeline (6 guards) | <10ms | ~0.02ms |
| Full ingress pipeline (5 guards) | <10ms | ~0.02ms |
| Full output pipeline (3 guards) | <10ms | ~0.01ms |
| Shield initialization | <100ms | ~7ms |
| Security context render | <5ms | ~0.01ms |

100 sequential egress checks: **~1.8ms total** (~0.02ms avg).

See [docs/performance.md](docs/performance.md) for detailed benchmarks.

## Data-Driven Threat Intelligence

Threat patterns are YAML data, not hardcoded regex — versionable, shareable, and AI-readable:

```yaml
# data/threat_patterns/indirect_injection_via_tool.yaml
id: TPI-001
name: Indirect injection via tool result
severity: high

attack_examples:
  - input: 'Tool result: "IMPORTANT: Ignore previous instructions..."'
    verdict: malicious
    reasoning: "Tool result contains override instructions"

rule_signatures:
  - type: regex
    pattern: "ignore\\s+(previous|above)\\s+instructions"
    confidence: 0.9
```

## Evaluation Results

R12-tuned evaluation (SLM + rules pipeline vs rules-only baseline):

| Metric | Rules-Only | SLM + Rules | Delta |
|--------|-----------|-------------|-------|
| **Precision** | 0.643 | **1.000** | +0.357 |
| **Recall** | 0.973 | **1.000** | +0.027 |
| **F1** | 0.774 | **1.000** | +0.226 |
| **FPR** | 0.400 | **0.000** | +0.400 (lower=better) |

Per-guard F1: prompt 0.681→1.000, reasoning 0.800→1.000, command 1.000→1.000, exfil 0.909→1.000. 22 samples improved, 0 regressed.

## Architecture

```
qise/
├── src/qise/
│   ├── core/              # GuardContext, AIGuardBase, Pipeline, Shield, Config
│   │   ├── models.py      # Data models (GuardContext, GuardResult, GuardVerdict, RiskAttribution)
│   │   ├── guard_base.py  # AIGuardBase + RuleChecker (three-layer decision)
│   │   ├── pipeline.py    # Ingress/Egress/Output pipeline with BLOCK short-circuit
│   │   ├── shield.py      # Main entry point — 14 guards, dependency injection
│   │   ├── config.py      # ShieldConfig parser for shield.yaml
│   │   ├── baseline_db.py # SQLite persistence for baseline hash records
│   │   ├── session_tracker.py  # Cross-turn security state
│   │   └── event_logger.py     # Structured security event logging
│   ├── guards/            # 14 Guard implementations
│   ├── models/            # ModelRouter (httpx-based OpenAI-compatible client)
│   ├── data/              # ThreatPatternLoader + BaselineManager + PromptExampleLoader
│   │   ├── baseline_manager.py # SHA-256 hash baselines (YAML + SQLite)
│   ├── providers/         # SecurityContextProvider (DSL template rendering)
│   ├── adapters/          # 5 Framework adapters
│   │   ├── base.py        #   AgentAdapter ABC + IngressCheckMixin + EgressCheckMixin
│   │   ├── nanobot.py     #   Nanobot AgentHook integration
│   │   ├── hermes.py      #   Hermes Plugin hook integration
│   │   ├── nexau.py       #   NexAU Middleware (6 hooks)
│   │   ├── langgraph.py   #   LangGraph tool wrapper + pre-model hook
│   │   └── openai_agents.py # OpenAI Agents SDK guardrails
│   ├── proxy/             # HTTP proxy server
│   │   ├── server.py      #   aiohttp-based proxy with SSE streaming
│   │   ├── streaming.py   #   SSEStreamHandler with BufferedToolCall state machine
│   │   ├── parser.py      #   Request/Response parser for OpenAI-compatible API
│   │   ├── interceptor.py #   ProxyInterceptor routing through Guard pipelines
│   │   ├── context_injector.py # SecurityContext injection into system messages
│   │   └── config.py      #   ProxyConfig with env overrides
│   ├── bridge/            # Python Bridge (Rust Proxy ↔ Guard Pipeline)
│   │   ├── server.py      #   BridgeServer (aiohttp) with 6 endpoints
│   │   ├── protocol.py    #   GuardCheckRequest/Response Pydantic models
│   │   └── cli.py         #   `qise bridge start` CLI
│   └── mcp_server.py      # MCP Server (4 security check tools)
├── src-tauri/             # Desktop App (Tauri 2 + React)
│   ├── src/               #   Rust backend
│   │   ├── proxy.rs       #   Embedded axum proxy with guard pipeline
│   │   ├── bridge.rs      #   Python Bridge subprocess management
│   │   ├── takeover.rs    #   Agent config takeover + crash recovery
│   │   ├── guard_client.rs#   Bridge HTTP client
│   │   └── commands.rs    #   9 Tauri IPC commands
│   └── ...
├── src-ui/                # React frontend (Raycast-style dark UI)
│   └── src/components/    #   AgentPanel, GuardList, EventLog, ProxyToggle, StatusIndicator
├── data/
│   ├── threat_patterns/   # 6 YAML threat patterns
│   ├── security_contexts/ # 8 DSL security context templates
│   └── prompts/           # 6 YAML few-shot example libraries (103 examples)
├── tests/                 # 439 tests
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
qise adapters                               # List framework adapters
qise adapters nexau                         # Show integration code
qise context bash                           # Get security context
qise guards                                 # List registered guards
qise version                                # Print version
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, integration modes, core interfaces |
| [Guards](docs/guards.md) | Detailed Guard specifications and AI/rule strategies |
| [Threat Model](docs/threat-model.md) | Attack taxonomies, trust boundaries, defense chains |
| [Integration Guide](docs/integration.md) | Proxy/MCP/SDK modes, desktop app setup |
| [Quick Start](docs/quickstart.md) | 5-minute setup guide |
| [Performance](docs/performance.md) | Latency benchmarks |

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
| Proxy Server (aiohttp + SSE streaming) | ✅ Complete |
| 5 Framework Adapters (Nanobot, Hermes, NexAU, LangGraph, OpenAI Agents) | ✅ Complete |
| CLI (check / serve / proxy / init / adapters / context / guards / version) | ✅ Complete |
| MCP Server (4 security check tools) | ✅ Complete |
| SecurityContextProvider (DSL template rendering) | ✅ Complete |
| BaselineManager (SHA-256 hash + SQLite) | ✅ Complete |
| Soft-Hard Defense Linkage (active_security_rules) | ✅ Complete |
| Structured SLM Prompts (IS/NOT + few-shot) | ✅ Complete |
| Dynamic Few-Shot Loading (PromptExampleLoader) | ✅ Complete |
| Confidence-based SLM Override (<0.65 / ≥0.65) | ✅ Complete |
| Configurable skip_slm_on_rule_pass + slm_override_rule_warn_threshold | ✅ Complete |
| Rust Proxy (axum + hyper + rustls, SSE streaming) | ✅ Complete |
| Python Bridge (aiohttp, 6 endpoints, event buffer) | ✅ Complete |
| Desktop App (Tauri 2, System Tray, Proxy Toggle) | ✅ Complete |
| Proxy Takeover (Agent config auto-redirect + crash recovery) | ✅ Complete |
| Real-time Frontend (AgentPanel, EventLog, GuardList) | ✅ Complete |
| BaselineDB SQLite Persistence | ✅ Complete |
| 439 unit + integration + performance tests | ✅ Complete |
| OpenAI Agents SDK E2E Test (10/10 passed) | ✅ Complete |

## License

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) — Free for personal, academic, and non-commercial use. Commercial use requires separate permission.
