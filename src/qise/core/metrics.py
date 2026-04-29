"""GuardMetrics — runtime metrics collection for guards and pipelines.

Collects invocation counts, verdict distributions, and latency histograms
in-memory. No external dependencies (Prometheus, StatsD, etc.) — pure Python.

Exposure:
  1. Shield.get_metrics() → dict (for Proxy/SDK)
  2. qise guards --metrics → CLI summary
  3. Proxy response header X-Qise-Metrics → brief summary
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class GuardMetrics:
    """Collect runtime metrics for guards and pipelines.

    Thread-safe: all mutations are protected by a lock.
    """

    # Counters
    guard_invocations: dict[str, int] = field(default_factory=dict)
    guard_verdicts: dict[str, Counter] = field(default_factory=dict)

    # Latency histograms (list of millisecond values per guard)
    guard_latency_ms: dict[str, list[int]] = field(default_factory=dict)

    # Session-level counters
    active_sessions: int = 0
    total_sessions: int = 0

    # Pipeline-level
    pipeline_invocations: dict[str, int] = field(default_factory=dict)  # pipeline_name → count
    pipeline_blocks: dict[str, int] = field(default_factory=dict)  # pipeline_name → block count

    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_guard_check(
        self,
        guard_name: str,
        verdict: str,
        latency_ms: int | None = None,
    ) -> None:
        """Record a single guard check result.

        Args:
            guard_name: Name of the guard (e.g., "command", "prompt").
            verdict: Verdict string ("pass", "warn", "block").
            latency_ms: Check latency in milliseconds, if available.
        """
        with self._lock:
            self.guard_invocations[guard_name] = self.guard_invocations.get(guard_name, 0) + 1

            if guard_name not in self.guard_verdicts:
                self.guard_verdicts[guard_name] = Counter()
            self.guard_verdicts[guard_name][verdict] += 1

            if latency_ms is not None:
                if guard_name not in self.guard_latency_ms:
                    self.guard_latency_ms[guard_name] = []
                self.guard_latency_ms[guard_name].append(latency_ms)
                # Keep at most 1000 latency samples per guard
                if len(self.guard_latency_ms[guard_name]) > 1000:
                    self.guard_latency_ms[guard_name] = self.guard_latency_ms[guard_name][-500:]

    def record_pipeline_run(
        self,
        pipeline_name: str,
        blocked: bool = False,
    ) -> None:
        """Record a pipeline run result.

        Args:
            pipeline_name: "ingress", "egress", or "output".
            blocked: Whether the pipeline resulted in a block.
        """
        with self._lock:
            self.pipeline_invocations[pipeline_name] = self.pipeline_invocations.get(pipeline_name, 0) + 1
            if blocked:
                self.pipeline_blocks[pipeline_name] = self.pipeline_blocks.get(pipeline_name, 0) + 1

    def record_session_start(self) -> None:
        """Record a new session."""
        with self._lock:
            self.active_sessions += 1
            self.total_sessions += 1

    def record_session_end(self) -> None:
        """Record a session ending."""
        with self._lock:
            self.active_sessions = max(0, self.active_sessions - 1)

    def snapshot(self) -> dict:
        """Return current metrics as a flat dict.

        Suitable for JSON serialization, logging, or API responses.
        """
        with self._lock:
            result: dict = {
                "active_sessions": self.active_sessions,
                "total_sessions": self.total_sessions,
                "guard_invocations": dict(self.guard_invocations),
                "guard_verdicts": {k: dict(v) for k, v in self.guard_verdicts.items()},
                "pipeline_invocations": dict(self.pipeline_invocations),
                "pipeline_blocks": dict(self.pipeline_blocks),
            }

            # Compute latency stats
            latency_stats: dict[str, dict] = {}
            for guard_name, latencies in self.guard_latency_ms.items():
                if not latencies:
                    continue
                sorted_lat = sorted(latencies)
                n = len(sorted_lat)
                latency_stats[guard_name] = {
                    "count": n,
                    "avg_ms": round(sum(sorted_lat) / n),
                    "min_ms": sorted_lat[0],
                    "max_ms": sorted_lat[-1],
                    "p50_ms": sorted_lat[n // 2],
                    "p95_ms": sorted_lat[int(n * 0.95)] if n > 1 else sorted_lat[0],
                    "p99_ms": sorted_lat[int(n * 0.99)] if n > 1 else sorted_lat[0],
                }
            result["guard_latency"] = latency_stats

            return result

    def brief(self) -> str:
        """Return a brief one-line summary for HTTP headers."""
        total_invocations = sum(self.guard_invocations.values())
        total_blocks = sum(
            v.get("block", 0) for v in self.guard_verdicts.values()
        )
        return f"invocations={total_invocations} blocks={total_blocks} sessions={self.total_sessions}"

    def reset(self) -> None:
        """Reset all counters (useful for testing)."""
        with self._lock:
            self.guard_invocations.clear()
            self.guard_verdicts.clear()
            self.guard_latency_ms.clear()
            self.active_sessions = 0
            self.total_sessions = 0
            self.pipeline_invocations.clear()
            self.pipeline_blocks.clear()


class MetricsTimer:
    """Context manager to measure and record guard check latency.

    Usage:
        with MetricsTimer(metrics, "command") as t:
            result = guard.check(context)
        # t.elapsed_ms is set, metrics.record_guard_check called automatically
    """

    def __init__(self, metrics: GuardMetrics, guard_name: str) -> None:
        self._metrics = metrics
        self._guard_name = guard_name
        self._start: float = 0.0
        self.elapsed_ms: int = 0

    def __enter__(self) -> MetricsTimer:
        self._start = time.monotonic()
        return self

    def __exit__(self, *args: object) -> None:
        self.elapsed_ms = int((time.monotonic() - self._start) * 1000)
