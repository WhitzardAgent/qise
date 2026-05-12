# Qise - AI Agent Security Framework

## Commands
- Install (Python engine): `pip install -e ".[dev]"`
- Install (Desktop app): `cd src-tauri && cargo tauri dev`
- Test: `pytest -x`
- Lint: `ruff check .`
- Format: `ruff format .`
- Type check: `mypy src/qise`
- Start proxy (CLI): `qise proxy start --port 8822`

## Stack
- **Python Engine** (qise-core): Python 3.11+, Pydantic v2, async/await
- **Desktop App**: Tauri 2 (Rust backend + React frontend)
- **Proxy Server**: axum + hyper + rustls (Rust, in Tauri backend)
- **Bridge**: Rust ↔ Python via HTTP (localhost)

## Architecture
- **Integration Layer** (3 modes):
  - Mode A: Proxy (zero-code, intercepts Agent↔LLM traffic)
  - Mode B: MCP (zero-code, registers as MCP server)
  - Mode C: SDK (code integration, framework adapters)
- **src/qise/core/**: GuardContext, GuardBase, AIGuardBase, Pipeline, Shield
- **src/qise/guards/**: Individual Guard implementations
- **src/qise/models/**: ModelRouter, SLM/LLM/Embedding clients
- **src/qise/adapters/**: Framework adapters (OpenClaw, Hermes, Nanobot, OpenHands)
- **src/qise/providers/**: SecurityContextProvider and DSL rendering
- **src/qise/data/**: Threat pattern loading, baseline management, YAML parsing
- **src/qise/proxy/**: Proxy mode Python bridge server
- **src-tauri/**: Desktop app (Rust backend + React frontend)

## Rules
- Every Guard MUST inherit from AIGuardBase (even rule-only guards — set primary_strategy="rules")
- NEVER fail-open: when models are unavailable, fall back to rules, never silently pass
- All GuardResults MUST include risk_attribution when AI was used
- YAML threat patterns in data/threat_patterns/ are the source of truth for attack signatures
- Adapters MUST NOT monkey-patch framework internals — use official Hook/Plugin APIs only
- Proxy mode MUST support crash recovery (auto-restore Agent config on exit/crash)
- Proxy mode MUST handle SSE streaming without blocking text responses
- Observe-first: default action is WARN/LOG, not BLOCK — users opt into blocking
- Prompt templates belong in code (slm_prompt_template / llm_prompt_template), not in YAML
- All async functions use `async def`, never `asyncio.run()` inside library code

## Project Files
- Full architecture doc: @docs/architecture.md
- Guard specifications: @docs/guards.md
- Threat model: @docs/threat-model.md
- Integration guide: @docs/integration.md
- Blueprint (design source): @../blue_print.md
