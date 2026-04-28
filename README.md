<div align="center">

# 🧀 Qise

**AI-First Runtime Security Framework for AI Agents**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Tests: 263 passed](https://img.shields.io/badge/Tests-263%20passed-brightgreen.svg)](tests/)
[![Guards: 14](https://img.shields.io/badge/Guards-14-orange.svg)](src/qise/guards/)

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
│   │  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────┐ ┌──────┐ │ │
│   │  │ Command │ │Filesystem│ │Network │ │Exfil │ │Policy│ │ │
│   │  │  Guard  │ │  Guard   │ │ Guard  │ │Guard │ │Guard │ │ │
│   │  └─────────┘ └──────────┘ └────────┘ └──────┘ └──────┘ │ │
│   │                         + ResourceGuard                    │ │
│   │                                                           │ │
│   │  Output (Audit)                                           │ │
│   │  ┌───────────┐ ┌──────────┐ ┌──────────┐                 │ │
│   │  │Credential │ │  Audit   │ │  Output  │                 │ │
│   │  │   Guard   │ │  Guard   │ │  Guard   │                 │ │
│   │  └───────────┘ └──────────┘ └──────────┘                 │ │
│   └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│   ┌─── Shared Services ──────────────────────────────────────┐ │
│   │  ModelRouter (SLM <50ms + LLM <2s) │ ThreatPatternLoader │ │
│   │  BaselineManager (SHA-256) │ SessionTracker │ EventLogger │ │
│   └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Why Qise

| Problem | Existing Solutions | Qise |
|---------|-------------------|------|
| Keyword rules easily bypassed | XSafeClaw: fuzzy matching (0.82 threshold) | AI understands attack semantics |
| Single model bottleneck | XSafeClaw: only 4B model | SLM <50ms fast-screen + LLM deep analysis |
| Fail-open on model errors | XSafeClaw & Lakera pass through | Rule fallback — **never fail-open** |
| No exfiltration detection | No open-source solution covers this | ExfilGuard: AI-first data exfil detection |
| No tool poisoning detection | No open-source solution covers this | ToolSanityGuard: hash baseline + AI |
| Static safety instructions | SAFETY.md (Agent can ignore) | Dynamic context + Guard enforcement |
| Requires code changes | Most solutions need integration | Proxy mode: zero-code, one-click |

## Three-Layer Decision Flow

Every guard uses the same decision flow — rules first for speed, AI for semantics, rules last for safety:

```
  ┌──────────────────┐
  │ Rule Fast-Path   │  <1ms — deterministic BLOCK or PASS
  │ (regex, hash,    │  e.g., "rm -rf /" → BLOCK
  │  patterns)       │  e.g., matching hash → PASS
  └────────┬─────────┘
           │ uncertain
           ▼
  ┌──────────────────┐
  │ SLM Fast-Screen  │  <50ms — semantic classification
  │ (≤4B model)      │  e.g., obfuscated command → BLOCK
  └────────┬─────────┘  e.g., paraphrased injection → ESCALATE
           │ low confidence
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
pip install -e ".[dev]"
```

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

### Python SDK

```python
from qise import Shield

shield = Shield.from_config()

# Check a tool call before execution
result = shield.pipeline.run_egress(GuardContext(
    tool_name="bash",
    tool_args={"command": "rm -rf /"},
))
print(result.verdict)  # "block"
```

### Run Tests

```bash
pytest tests/ -v    # 263 tests
```

## 14 Guards at a Glance

### Ingress Pipeline (World → Agent)

| Guard | Strategy | Detects |
|-------|----------|---------|
| **PromptGuard** | AI-first (80/20) | Indirect injection, multi-turn attacks, context poisoning |
| **ReasoningGuard** | AI-only (100/0) | Manipulation traces in chain-of-thought |
| **ToolSanityGuard** | AI-first (80/20) | Tool description poisoning, rug pulls, name shadowing |
| **ContextGuard** | AI+hash (70/30) | Memory/KB poisoning, data tampering, hash integrity |
| **SupplyChainGuard** | AI+rules (60/40) | Malicious Skills, MCP tampering, source verification |

### Egress Pipeline (Agent → World)

| Guard | Strategy | Detects |
|-------|----------|---------|
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

## Model Layer

| Tier | Model | Latency | Usage |
|------|-------|---------|-------|
| SLM fast-screen | Qwen3-4B / Phi-4-mini | <50ms | Every tool call (AI-first guards) |
| LLM deep analysis | Claude / GPT / Qwen-72B | <2s | Only when SLM escalates (~5%) |
| Rule fallback | Deterministic rules | <1ms | When models unavailable (never fail-open) |

**Stub mode**: Works out of the box without any model server — all guards degrade to rules gracefully.

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
│   │   ├── session_tracker.py  # Cross-turn security state
│   │   └── event_logger.py     # Structured security event logging
│   ├── guards/            # 14 Guard implementations
│   │   ├── prompt.py      #   Ingress: AI-first injection detection
│   │   ├── reasoning.py   #   Ingress: AI-only chain-of-thought analysis
│   │   ├── tool_sanity.py #   Ingress: AI-first tool poisoning + rug pulls
│   │   ├── context.py     #   Ingress: AI+hash memory/KB poisoning
│   │   ├── supply_chain.py#   Ingress: AI+rules source/hash verification
│   │   ├── command.py     #   Egress: Rules-first command analysis
│   │   ├── filesystem.py  #   Egress: Rules workspace/path protection
│   │   ├── network.py     #   Egress: Rules SSRF/domain blocking
│   │   ├── exfil.py       #   Egress: AI-first data exfiltration
│   │   ├── resource.py    #   Egress: Rules+AI loop/budget/breaker
│   │   ├── tool_policy.py #   Egress: Rules deny/approval/owner-only
│   │   ├── credential.py  #   Output: Rules credential regex
│   │   ├── audit.py       #   Output: Rules+AI attack chain + logging
│   │   └── output.py      #   Output: AI+rules PII/KB leak detection
│   ├── models/            # ModelRouter (httpx-based OpenAI-compatible client)
│   ├── data/              # ThreatPatternLoader + BaselineManager
│   ├── providers/         # SecurityContextProvider (DSL template rendering)
│   ├── adapters/          # Framework adapters (coming soon)
│   └── mcp_server.py      # MCP Server (4 security check tools)
├── data/
│   ├── threat_patterns/   # 6 YAML threat patterns
│   └── security_contexts/ # 5 DSL security context templates
├── tests/                 # 263 tests
└── docs/                  # Architecture, Guards, Threat Model, Integration
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, integration modes, core interfaces |
| [Guards](docs/guards.md) | Detailed Guard specifications and AI/rule strategies |
| [Threat Model](docs/threat-model.md) | Attack taxonomies, trust boundaries, defense chains |
| [Integration Guide](docs/integration.md) | Proxy/MCP/SDK modes, desktop app setup |
| [Data Formats](docs/data-formats.md) | YAML threat patterns, security context DSL, baselines |
| [Roadmap](docs/roadmap.md) | Development phases and milestones |

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
| BaselineManager (SHA-256 hash integrity) | ✅ Complete |
| ThreatPatternLoader (YAML threat patterns) | ✅ Complete |
| MCP Server (4 security check tools) | ✅ Complete |
| SessionTracker + EventLogger | ✅ Complete |
| 263 unit + integration tests | ✅ Complete |
| Proxy server (Rust/axum) | 🔜 Phase 4 |
| Desktop App (Tauri 2) | 🔜 Phase 4 |
| Framework adapters | 🔜 Phase 3 |

## License

Apache 2.0
