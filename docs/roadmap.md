# Roadmap

## Completed

### Phase 1: Core Engine ✅ (Rounds 1-5)

- `GuardContext`, `GuardResult`, `GuardVerdict`, `RiskAttribution` data models
- `AIGuardBase` with three-layer decision (rule → SLM → LLM → rule fallback)
- `GuardPipeline` with Ingress/Egress/Output pipeline execution
- `Shield` entry point with `from_config()`, `check()`, `check_tool_call()`
- `ModelRouter` with OpenAI-compatible client for SLM/LLM/Embedding
- `ShieldConfig` parser for `shield.yaml`
- `SessionTracker` for cross-turn security state
- `EventLogger` for structured security event logging
- 14 Guards (all implemented)
- SecurityContextProvider (5 DSL templates)
- ReasoningGuard (SLM reasoning analysis + threshold adjustment)
- MCP Server (4 tools)
- CLI (check, serve, context, guards, version)
- 6 threat pattern YAMLs + 5 security context DSL templates

### Phase 2: Agent → World Guards ✅ (Rounds 3-4)

- FilesystemGuard: path traversal, workspace boundaries
- NetworkGuard: SSRF, CIDR blocking
- ExfilGuard: AI-first data exfiltration detection
- ResourceGuard: loop detection, budget enforcement
- AuditGuard: structured logging and event correlation

### Phase 3: World → Agent + SDK Adapters + Proxy ✅ (Rounds 4-10)

- ToolSanityGuard: tool description poisoning + hash baseline
- ContextGuard: Memory/KB poisoning + hash integrity
- SupplyChainGuard: Skills/KB scanning + MCP verification
- OutputGuard: KB content leak + PII detection
- ToolPolicyGuard: profile-based tool access control
- Python HTTP proxy server (aiohttp) with SSE streaming
- 5 Framework Adapters: Nanobot, Hermes, NexAU, LangGraph, OpenAI Agents SDK
- Architecture fixes: fallback strategy, threshold accumulation, default modes, soft-hard linkage
- CLI: 8 subcommands (check, serve, proxy, init, adapters, context, guards, version)
- 4 real-world integration examples
- 393 tests
- License: CC BY-NC-SA 4.0

---

## Planned

### Phase 4: Desktop App + Advanced Features

#### Desktop App (Tauri 2)
- System tray with one-click toggle, status indicator, blocked event count
- Main window with Guard Dashboard (real-time security events)
- Proxy Panel (select agents, configure takeover, view intercepted traffic)
- MCP Panel (auto-register/unregister)
- Policy Editor (visual guard toggles, threshold sliders)
- SQLite database for events and configuration
- macOS code signing and notarization

#### Rust Proxy Server
- High-performance HTTP proxy (axum + hyper + rustls)
- Python↔Rust HTTP Bridge
- Proxy takeover: auto-configure Agent API settings, crash recovery

#### Guard Enhancements
- AuditGuard upgrade: attack chain reconstruction, session security scoring
- MultiAgentGuard: multi-agent scenarios
- ContextGuard periodic scanning: scheduled re-evaluation

#### Data Intelligence
- Auto-generation of risk rules from runtime observation data
- Threat pattern versioning and community sharing
- More threat pattern YAMLs (10+ total)
- Red team evaluation dataset

#### Proxy Advanced
- Multi-agent simultaneous protection
- Non-OpenAI-compatible API support (Anthropic native, Google native)
- MCP Firewall mode: proxy all MCP communication

#### SLM Fine-tuning
- Security classification dataset construction
- LoRA fine-tuning on Qwen3-4B for injection + reasoning detection
- Target: T1 accuracy 85-90%, T3 accuracy 80-85%
- Dedicated QiseGuard-4B multi-task security SLM (v1.0+)
