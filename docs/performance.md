# Performance

Qise is designed for minimal overhead. In rule-only mode (no SLM/LLM), latency is sub-millisecond for individual guards and sub-10ms for full pipelines.

## Latency Budgets

| Operation | Target | Measured (p95) |
|-----------|--------|----------------|
| Rule fast-path (single guard) | <1ms | ~0.02ms |
| Full egress pipeline (6 guards) | <10ms | ~0.02ms |
| Full ingress pipeline (5 guards) | <10ms | ~0.02ms |
| Full output pipeline (3 guards) | <10ms | ~0.01ms |
| Shield initialization | <100ms | ~7ms |
| Security context render | <5ms | ~0.01ms |

## Rule Fast-Path Detail

| Guard | Scenario | Measured (p95) |
|-------|----------|----------------|
| CommandGuard | Block `rm -rf /` | ~0.00ms |
| CommandGuard | Pass `ls -la` | ~0.02ms |
| CredentialGuard | Detect AWS key | ~0.01ms |
| FilesystemGuard | Block `/etc/passwd` write | ~0.01ms |
| NetworkGuard | Block SSRF `169.254.169.254` | ~0.02ms |

## Sequential Throughput

| Scenario | 100 checks total | Avg per check |
|----------|-----------------|---------------|
| Egress (safe) | ~1.8ms | ~0.02ms |
| Ingress (safe) | ~1.5ms | ~0.01ms |

## Latency with SLM

When an SLM model is configured, AI-first guards such as PromptGuard add model-call latency. The current MVP treats this as an optional second layer:

| Path | Expected behavior |
|------|-------------------|
| Rule fast-path | Sub-millisecond local checks; this remains the default protection layer |
| Local SLM via Ollama, e.g. `qwen3:4b` | Hardware and model dependent; on a laptop this can be seconds, not milliseconds |
| Custom optimized security SLM | Future target for low-latency semantic screening |

If the SLM endpoint is slow or unavailable, Qise times out and falls back to rule-based decisions or conservative warnings. Check readiness with `qise slm status` and `qise doctor`.

## Performance Testing

Run the performance baseline suite:

```bash
pytest tests/test_performance.py -v -s
```

The performance suite covers the rule-only fast path. Real SLM latency should be measured separately for the selected model and hardware.
