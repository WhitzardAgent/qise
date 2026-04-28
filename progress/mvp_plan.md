# Qise MVP Plan — From Current State to Releasable Version

**Date**: 2026-04-28 (updated)
**Current State**: 14 Guards, 393 tests, 5 Framework Adapters, Proxy + SSE streaming, CLI 8 subcommands

---

## Milestone Overview

```
v0.1 ✅ ──────→ v0.5 ✅ ──────→ v1.0 🔜
(14 guards)    (+proxy+SSE)    (+desktop)
 393 tests      +adapters      ~500+ tests
 5 adapters     +examples
```

---

## v0.1 — Python SDK + MCP ✅ COMPLETE

**Delivered in Rounds 1-5**:

- 14 Guards (Ingress + Egress + Output) — all implemented
- ModelRouter (httpx-based OpenAI-compatible client)
- CLI: check, serve, context, guards, version
- MCP Server (4 security check tools)
- SecurityContextProvider (DSL template rendering)
- BaselineManager (SHA-256 hash integrity)
- SessionTracker + EventLogger
- 6 YAML threat patterns + 5 DSL security context templates
- ~288 tests

## v0.5 — Proxy + Adapters + Architecture ✅ COMPLETE

**Delivered in Rounds 6-10**:

- Python HTTP proxy server (aiohttp) with SSE streaming support
- SSEStreamHandler with BufferedToolCall state machine
- Request/Response parser (OpenAI-compatible API)
- ProxyInterceptor routing through Guard pipelines
- ContextInjector for SecurityContext injection
- 5 Framework Adapters:
  - QiseNanobotHook (AgentHook integration)
  - QiseHermesPlugin (Plugin hook integration)
  - QiseNexauMiddleware (6 middleware hooks)
  - QiseLangGraphWrapper (sync/async tool wrappers + pre-model hook)
  - QiseOpenAIAgentsGuardrails (4 guardrail functions)
- Architecture fixes (fallback strategy, threshold accumulation, default modes, soft-hard linkage)
- CLI: init, adapters, proxy start (8 subcommands total)
- 4 real-world integration examples
- 393 tests
- License: CC BY-NC-SA 4.0

## v1.0 — Desktop App 🔜 PLANNED

| # | Task | Size | Description |
|---|------|------|-------------|
| 1 | Rust proxy server (axum) | Large | High-performance HTTP proxy replacing Python version |
| 2 | Python↔Rust HTTP Bridge | Medium | Rust proxy calls Python Security Engine |
| 3 | Tauri 2 desktop app | Large | React UI + Rust backend |
| 4 | Security dashboard UI | Large | Real-time events, guard visualization |
| 5 | Performance optimization | Medium | Caching, batch checks, rule indexing |
| 6 | QiseGuard-4B SLM | Large | Dedicated multi-task security SLM |

---

## Guard Implementation Status

| Guard | Pipeline | Strategy | Rule Fast-Path | SLM | LLM | Round |
|-------|----------|----------|---------------|-----|-----|-------|
| PromptGuard | Ingress | AI-first | ✅ | ✅ | ✅ | Round 2 |
| ReasoningGuard | Ingress | AI-only | ❌ | ✅ | ❌ | Round 2 |
| ToolSanityGuard | Ingress | AI-first | ✅ | ✅ | ✅ | Round 4 |
| ContextGuard | Ingress | AI+hash | ✅ | ✅ | ✅ | Round 4 |
| SupplyChainGuard | Ingress | AI+rules | ✅ | ✅ | ✅ | Round 4 |
| CommandGuard | Egress | Rules-first | ✅ | ✅ | ❌ | Round 2 |
| FilesystemGuard | Egress | Rules | ✅ | ❌ | ❌ | Round 3 |
| NetworkGuard | Egress | Rules | ✅ | ❌ | ❌ | Round 3 |
| ExfilGuard | Egress | AI-first | ✅ | ✅ | ✅ | Round 3 |
| ResourceGuard | Egress | Rules-first | ✅ | ✅ | ❌ | Round 3 |
| ToolPolicyGuard | Egress | Rules | ✅ | ❌ | ❌ | Round 4 |
| CredentialGuard | Output | Rules | ✅ | ❌ | ❌ | Round 2 |
| AuditGuard | Output | Rules-first | ✅ | ✅ | ✅ | Round 3 |
| OutputGuard | Output | AI+rules | ✅ | ✅ | ❌ | Round 4 |

---

## Framework Adapter Status

| Adapter | Framework | Hook Points | Round |
|---------|-----------|-------------|-------|
| QiseNanobotHook | Nanobot | before_execute_tools, after_iteration | Round 7 |
| QiseHermesPlugin | Hermes | pre/post_tool_call, transform_result, post_llm_call | Round 7 |
| QiseNexauMiddleware | NexAU | before/after_agent, before/after_model, before/after_tool | Round 9 |
| QiseLangGraphWrapper | LangGraph | wrap/awrap_tool_call, pre_model_hook | Round 9 |
| QiseOpenAIAgentsGuardrails | OpenAI Agents | input/output_guardrail, tool_input/output_guardrail | Round 9 |

---

## Model Strategy

### Phase 1: General SLM + Prompt (v0.1 ✅ — available now)

- SLM: Qwen3-4B / Phi-4-mini with guard-specific prompt templates
- LLM: Claude Sonnet / GPT-4o-mini via API
- Works in stub mode (rule-only) out of the box

### Phase 2: Security-classification SLM fine-tuning (v0.5 recommended)

- LoRA fine-tuning on T1 (injection classification) + T3 (reasoning manipulation)
- Training data: InjectLab + MCP-ITP + synthetic samples
- Expected: T1 accuracy 85-90%, T3 accuracy 80-85%

### Phase 3: Dedicated security SLM (v1.0+)

- QiseGuard-4B: multi-task security classification
- Unified input/output format across all AI tasks
- Expected: overall 95%+ detection rate
