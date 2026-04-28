# Roadmap

## Phase 1: Core Engine + Proxy Mode + Desktop App (10 weeks)

**Goal**: Working security framework with proxy-based zero-code protection and desktop app.

### Core Engine (Python)
- `GuardContext`, `GuardResult`, `GuardVerdict`, `RiskAttribution` data models
- `AIGuardBase` with three-layer decision (rule → SLM → LLM → rule fallback)
- `GuardPipeline` with Ingress/Egress/Output pipeline execution
- `Shield` entry point with `from_config()`, `check()`, `check_tool_call()`
- `ModelRouter` with OpenAI-compatible client for SLM/LLM/Embedding
- `ShieldConfig` parser for `shield.yaml`
- `SessionTracker` for cross-turn security state
- `EventLogger` for structured security event logging
- HTTP Bridge: Python server exposing Guard Pipeline via HTTP API (for Tauri integration)

### Hard Defense Guards
- **PromptGuard**: SLM fast-screen + rule fallback (highest priority — indirect injection is the most common attack)
- **CommandGuard**: Rule-first + SLM semantic variant detection
- **CredentialGuard**: Rule-only credential detection in output

### Soft Defense
- **SecurityContextProvider**: Scene-aware context injection + 5 DSL templates
- **ReasoningGuard**: SLM reasoning analysis + safety reminder injection + threshold adjustment signal
- Soft-hard defense linkage: ReasoningGuard threshold adjustments propagate to hard defense guards

### Proxy Mode (Rust + Python)
- Local HTTP proxy server (axum + hyper + rustls)
- OpenAI-compatible API request/response parsing
- Request interceptor: inject security context into system messages
- Response interceptor: parse tool_use and tool_result
- Tool call interception and Guard Pipeline execution
- SSE streaming support (incremental analysis)
- Proxy takeover: auto-configure Agent API settings, crash recovery
- Guard decision → proxy action mapping (PASS/WARN/BLOCK)

### MCP Mode
- MCP server implementation
- 4 tools: check_tool_call, check_content, check_output, get_security_context
- Auto-registration to Agent MCP configs

### Desktop App (Tauri 2)
- System tray with one-click toggle, status indicator, blocked event count
- Main window with Guard Dashboard (real-time security events)
- Proxy Panel (select agents, configure takeover, view intercepted traffic)
- MCP Panel (auto-register/unregister)
- Policy Editor (visual guard toggles, threshold sliders)
- SQLite database for events and configuration
- macOS code signing and notarization

### Data
- 3 threat pattern YAMLs: indirect_injection_via_tool, tool_poisoning, memory_kb_poisoning
- 5 security context DSL templates: database, filesystem, network, shell, KB access
- SLM deployment script (AgentDoG-Qwen3-4B or Qwen3-4B + custom prompt)

### Tests
- Unit tests for all core components
- Proxy integration tests with mock LLM API
- Desktop app e2e tests
- Latency benchmarks (SLM <50ms, rules <1ms, proxy overhead <5ms)

---

## Phase 2: Agent → World Guards + ExfilGuard (6 weeks)

**Goal**: Complete coverage for agent actions affecting the external world.

### New Guards
- **FilesystemGuard**: Path traversal, workspace boundaries, system directory protection
- **NetworkGuard**: SSRF protection, CIDR blocking, post-redirect validation, DNS rebinding detection
- **ExfilGuard**: AI-first data exfiltration detection (key differentiator)
- **ResourceGuard**: Loop detection, budget enforcement, circuit breaker
- **AuditGuard**: Basic structured logging and event correlation

### Desktop App Enhancements
- Threat Explorer: browse threat pattern library, view attack examples
- Usage dashboard: guard latency/accuracy metrics, risk trend charts
- Guard detail view: per-guard event history and statistics

### Data
- More threat pattern YAMLs (10+ total)
- More SecurityContextProvider DSL templates
- Resource budget configuration

### Tests
- ExfilGuard evaluation against known exfiltration techniques
- NetworkGuard SSRF test suite
- ResourceGuard loop detection test suite

---

## Phase 3: World → Agent Full Coverage + SDK Adapters + KB Security (8 weeks)

**Goal**: Complete coverage for attacks targeting the agent, knowledge base security, and SDK mode for framework integration.

### New Guards
- **ToolSanityGuard**: Tool description poisoning detection + hash baseline rug pull detection
- **ContextGuard**: Memory + KB poisoning detection + hash integrity verification
- **SupplyChainGuard**: Skills/KB scanning + MCP verification
- **OutputGuard**: KB content leak detection + PII exposure detection
- **ToolPolicyGuard**: Profile-based tool access control

### Knowledge Base Security
- Trust boundary extension: `knowledge_base`, `tool_description`
- KB ingestion scanning: ContextGuard scans new documents before insertion
- Periodic KB audit: BaselineManager re-checks document hashes
- KB content leak detection in OutputGuard

### SDK Mode (Framework Adapters)
- **Nanobot adapter**: AgentHook integration
- **Hermes adapter**: Plugin system integration
- **OpenClaw adapter**: Plugin SDK integration
- **OpenHands adapter**: Hooks system integration
- Generic Python SDK (already in Phase 1)

### Desktop App Enhancements
- SDK Mode panel: code snippets, installation guide
- Integration mode selector (Proxy/MCP/SDK)
- Per-agent integration status

### Data
- KB-specific threat pattern YAMLs
- Tool baseline hash records
- KB baseline hash records
- Memory baseline hash records

### Evaluation
- Red team evaluation dataset
- Benchmark against InjectLab (25+ injection techniques)
- Comparison with XSafeClaw AgentDoG model

---

## Phase 4: Advanced Features (Ongoing)

### Guard Enhancements
- **AuditGuard upgrade**: Attack chain reconstruction, session security scoring
- **MultiAgentGuard**: Security for multi-agent scenarios (agent-to-agent communication)
- **ContextGuard periodic scanning**: Scheduled re-evaluation of all persistent context

### Data Intelligence
- Auto-generation of risk rules from runtime observation data
- Threat pattern versioning and community sharing
- A/B testing framework for guard configurations

### Desktop App Advanced
- Visualization dashboard for security events
- Guard performance analytics (latency, accuracy, false positive rate)
- Configuration migration tooling (shield.yaml version upgrades)
- Deep link import for policies (`qise://policy/...`)
- Cloud sync for policies via WebDAV/Dropbox/iCloud
- Multi-language support (Chinese, English, Japanese)

### Proxy Advanced
- Multi-agent simultaneous protection
- Proxy health monitoring and auto-recovery
- Custom request/response transformation rules
- Non-OpenAI-compatible API support (Anthropic native, Google native)

### MCP Advanced
- **MCP Firewall mode**: Proxy all MCP communication through Qise
- MCP server integrity verification
- MCP tool registration monitoring

### SecurityContextProvider Intelligence
- Dynamic optimization of DSL templates based on runtime data
- Personalized security rules based on observed agent behavior patterns
- Community-contributed security context templates

### Research Integration
- Custom SLM fine-tuning pipeline for security-specific tasks
- Integration with AI-Infra-Guard for offline scanning (complementary)
- Evaluation against latest attack research papers
