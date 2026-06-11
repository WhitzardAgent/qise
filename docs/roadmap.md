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
- 500+ automated tests
- License: CC BY-NC-SA 4.0

### Phase 4: Desktop App + Product Runtime ✅

#### Desktop App (Tauri 2)
- System tray and desktop dashboard
- Agent detection, one-click protection, backup, and restore
- Preflight scanning for Agent configs, Skills, and MCP assets
- Security event, guard policy, SLM, diagnostics, and SDK views
- Shared Python product engine for CLI and desktop behavior
- macOS and Windows installer build pipelines

#### Product Runtime
- Python HTTP proxy and Bridge managed by the Qise CLI
- Automatic Agent configuration backup and proxy takeover
- Runtime state validation and stale-service recovery

---

## Planned

### Phase 5: Advanced Features

#### Release Hardening
- macOS notarization and signed Windows distribution
- Installer auto-update and release-channel support
- Expanded desktop end-to-end automation

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
