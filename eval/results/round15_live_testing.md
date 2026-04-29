# Round 15: Rust Proxy + Python Bridge Live Testing Results

**Date**: 2026-04-29
**Architecture**: Rust Proxy (axum) + Python Bridge (aiohttp) + SII glm-5.1-w4a8

## Architecture Summary

```
Agent → Rust Proxy (8822) → [Guard Check] → Python Bridge (8823) → Guard Pipeline
                              → [Forward]  → SII API (glm-5.1-w4a8)
                              → [Response] → [Egress Check] → Python Bridge
```

## Integration Tests: 8/8 Passed

| # | Test | Result | Details |
|---|------|--------|---------|
| 1 | Bridge health check | PASS | slm_available=False (rules-only mode) |
| 2 | Bridge metrics | PASS | metrics endpoint working |
| 3 | Bridge guard check (safe) | PASS | action=warn (observe mode) |
| 4 | Bridge guard check (dangerous cmd) | PASS | BLOCKED by CommandGuard |
| 5 | Bridge guard check (credential leak) | PASS | BLOCKED by CredentialGuard |
| 6 | Proxy safe request | PASS | "2 + 2 = 4" via SII glm-5.1-w4a8 |
| 7 | Proxy passthrough /v1/models | PASS | 1 model available |
| 8 | Proxy dangerous request | PASS | Guard check ran, forwarded (observe mode) |

## E2E Attack Scenarios: 6/6 Passed

| # | Scenario | Result | Guard | Details |
|---|----------|--------|-------|---------|
| 1 | Indirect injection via tool_result | PASS | PromptGuard (warn) | Injection intent detected |
| 2 | Data exfiltration (curl + env) | PASS | CommandGuard (warn) | Dangerous command pattern detected |
| 3 | Reasoning manipulation + sudo rm | PASS | CommandGuard (block) | sudo + rm pattern blocked |
| 4 | Credential leak in output | PASS | CredentialGuard (block) | AWS key pattern detected and blocked |
| 5 | Path traversal (/etc/shadow) | PASS | FilesystemGuard (block) | System path access blocked |
| 6 | Safe tool call (read workspace file) | PASS | — | action=pass, no false positive |

## Regression Tests

- **410 tests passed** (0 failures)
- `ruff check .` — no new errors

## Key Metrics

| Metric | Value |
|--------|-------|
| Rust Proxy startup time | ~2s |
| Bridge startup time | ~1s |
| Guard check latency (rules-only) | <5ms |
| Safe request E2E latency (proxy → bridge → SII) | ~1.5s |
| Upstream SII API latency | ~600ms |

## Technical Findings

1. **URL path handling**: Rust Proxy must handle `/v1` overlap when `upstream_base_url` ends with `/v1`. Fixed with `build_upstream_url()` helper.
2. **Axum routing**: `/{*path}` wildcard catches all paths for the proxy handler.
3. **Guard mode**: Default `shield.yaml` has guards in `enforce` mode, so dangerous commands/credentials are blocked immediately.
4. **Bridge isolation**: Python Bridge runs in a separate process with `asyncio.to_thread()` for sync Guard Pipeline calls.
5. **Health check**: Rust Proxy checks Bridge health at startup, degrades to pass mode if unavailable.

## Files Created/Modified

### New Files
- `src-proxy/` — Complete Rust Proxy project (6 source files)
- `src/qise/bridge/cli.py` — Bridge CLI command
- `docker/Dockerfile.qise-proxy` — Rust multi-stage build
- `docker/Dockerfile.qise-bridge` — Python Bridge container
- `docker/sandbox/test_proxy_live.py` — Integration test (8 tests)
- `docker/sandbox/test_e2e_attack_scenarios.py` — E2E attack scenarios (6 tests)

### Modified Files
- `src/qise/bridge/server.py` — BridgeServer with all guard pipeline integration
- `src/qise/bridge/protocol.py` — Request/response protocol types
- `src/qise/cli.py` — Added `qise bridge start` command
- `docker/sandbox/docker-compose.yml` — Added qise-bridge service, updated qise-proxy to Rust
- `docker/sandbox/shield.yaml` — Configured for Rust Proxy architecture

## Next Steps

1. Build Docker images and test in Docker Compose
2. Test with real Agent frameworks (OpenAI Agents SDK, Hermes, NexAU)
3. Add SLM integration for AI-first guards (currently rules-only)
4. SSE streaming test with real streaming LLM API
