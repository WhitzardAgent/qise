"""SessionTracker — in-memory cross-turn security state tracking.

Tracks guard results per session for multi-turn attack detection and
risk scoring. Uses a decaying weighted score where recent events
contribute more than older ones.
"""

from __future__ import annotations

from collections import defaultdict

from qise.core.models import GuardResult, GuardVerdict, ToolCallRecord


# Verdict weights for risk scoring
_VERDICT_WEIGHTS: dict[str, float] = {
    GuardVerdict.BLOCK: 1.0,
    GuardVerdict.APPROVE: 0.8,
    GuardVerdict.WARN: 0.5,
    GuardVerdict.ESCALATE: 0.4,
    GuardVerdict.PASS: 0.0,
}


class SessionTracker:
    """In-memory cross-turn security state tracker.

    All state is stored in dicts keyed by session_id. No persistence
    — if the process restarts, tracking state is lost.
    """

    def __init__(self) -> None:
        self._results: dict[str, list[GuardResult]] = defaultdict(list)
        self._tool_calls: dict[str, list[ToolCallRecord]] = defaultdict(list)

    def record_guard_result(self, session_id: str, result: GuardResult) -> None:
        """Record a guard result for a session."""
        self._results[session_id].append(result)

    def record_tool_call(self, session_id: str, record: ToolCallRecord) -> None:
        """Record a tool call for a session."""
        self._tool_calls[session_id].append(record)

    def get_risk_score(self, session_id: str) -> float:
        """Compute a decaying weighted risk score for a session.

        Recent results weigh more than older ones. Score is in [0.0, 1.0].
        Uses exponential decay: weight = base^(distance_from_end).
        """
        results = self._results.get(session_id, [])
        if not results:
            return 0.0

        decay = 0.9  # Each older result gets 90% of the previous weight
        total_weight = 0.0
        weighted_sum = 0.0

        for i, result in enumerate(results):
            distance = len(results) - 1 - i  # 0 for most recent
            weight = decay**distance
            score = _VERDICT_WEIGHTS.get(result.verdict, 0.0) * result.confidence
            weighted_sum += score * weight
            total_weight += weight

        return min(1.0, weighted_sum / total_weight) if total_weight > 0 else 0.0

    def is_under_attack(self, session_id: str, threshold: float = 0.6) -> bool:
        """Return True if the session's risk score exceeds the threshold."""
        return self.get_risk_score(session_id) >= threshold

    def get_recent_verdicts(
        self, session_id: str, count: int = 5
    ) -> list[GuardResult]:
        """Return the most recent guard results for a session."""
        results = self._results.get(session_id, [])
        return results[-count:]

    def get_tool_call_history(
        self, session_id: str, count: int = 20
    ) -> list[ToolCallRecord]:
        """Return recent tool call records for a session."""
        calls = self._tool_calls.get(session_id, [])
        return calls[-count:]

    def clear_session(self, session_id: str) -> None:
        """Clear all tracking state for a session."""
        self._results.pop(session_id, None)
        self._tool_calls.pop(session_id, None)
