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

When an SLM model is configured, AI-first guards (PromptGuard, ExfilGuard, etc.) add model call latency:

| Path | Latency | Frequency |
|------|---------|-----------|
| Rule fast-path | <1ms | ~60% of calls |
| SLM fast-screen | 30-50ms | ~35% of calls |
| LLM deep analysis | 1-3s | <5% of calls |

## Performance Testing

Run the performance baseline suite:

```bash
pytest tests/test_performance.py -v -s
```

All tests assert that p95 latency stays within the budget. If a test fails, it means a regression has increased latency beyond acceptable limits.
