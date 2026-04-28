"""ResourceGuard — rules + AI guard detecting infinite loops and resource exhaustion.

Monitors iteration count, detects repetitive tool call patterns,
and enforces budget limits (max iterations, API calls).
"""

from __future__ import annotations

from collections import Counter

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_MAX_ITERATIONS = 50
_DEFAULT_MAX_API_CALLS = 100
_DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class ResourceGuardRuleChecker(RuleChecker):
    """Deterministic resource and loop detection checks."""

    def __init__(
        self,
        max_iterations: int = _DEFAULT_MAX_ITERATIONS,
        max_api_calls: int = _DEFAULT_MAX_API_CALLS,
        circuit_breaker_threshold: int = _DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
    ) -> None:
        self.max_iterations = max_iterations
        self.max_api_calls = max_api_calls
        self.circuit_breaker_threshold = circuit_breaker_threshold

    def check(self, context: GuardContext) -> GuardResult:
        # 1. Iteration budget
        if context.iteration_count > self.max_iterations:
            return GuardResult(
                guard_name="resource",
                verdict=GuardVerdict.BLOCK,
                confidence=0.9,
                message=f"Iteration limit exceeded: {context.iteration_count} > {self.max_iterations}",
                risk_attribution=RiskAttribution(
                    risk_source="resource_exhaustion",
                    failure_mode="infinite_loop",
                    real_world_harm="cost_overrun",
                    confidence=0.9,
                    reasoning=f"Agent has exceeded {self.max_iterations} iterations",
                ),
            )

        # 2. API call budget
        call_count = len(context.tool_call_history)
        if call_count > self.max_api_calls:
            return GuardResult(
                guard_name="resource",
                verdict=GuardVerdict.BLOCK,
                confidence=0.9,
                message=f"API call limit exceeded: {call_count} > {self.max_api_calls}",
                risk_attribution=RiskAttribution(
                    risk_source="resource_exhaustion",
                    failure_mode="budget_overrun",
                    real_world_harm="cost_overrun",
                    confidence=0.9,
                    reasoning=f"Agent has exceeded {self.max_api_calls} API calls",
                ),
            )

        # 3. Loop detection: repetitive tool calls
        loop_result = self._check_loop(context)
        if loop_result is not None:
            return loop_result

        # 4. Circuit breaker: consecutive failures
        breaker_result = self._check_circuit_breaker(context)
        if breaker_result is not None:
            return breaker_result

        return GuardResult(guard_name="resource", verdict=GuardVerdict.PASS)

    def _check_loop(self, context: GuardContext) -> GuardResult | None:
        """Detect repetitive tool call patterns."""
        history = context.tool_call_history
        if len(history) < 5:
            return None

        recent = history[-5:]
        tool_names = [r.tool_name for r in recent]

        # If 3+ of the last 5 calls are the same tool, flag as loop
        counts = Counter(tool_names)
        most_common_name, most_common_count = counts.most_common(1)[0]

        if most_common_count >= 3:
            return GuardResult(
                guard_name="resource",
                verdict=GuardVerdict.WARN,
                confidence=0.8,
                message=f"Loop detected: '{most_common_name}' called {most_common_count} times in last 5 calls",
                risk_attribution=RiskAttribution(
                    risk_source="resource_exhaustion",
                    failure_mode="infinite_loop",
                    real_world_harm="cost_overrun",
                    confidence=0.8,
                    reasoning=f"Repetitive calls to '{most_common_name}' suggest agent is stuck",
                ),
            )

        return None

    def _check_circuit_breaker(self, context: GuardContext) -> GuardResult | None:
        """Detect consecutive failures (non-PASS verdicts)."""
        history = context.tool_call_history
        if len(history) < self.circuit_breaker_threshold:
            return None

        recent = history[-self.circuit_breaker_threshold:]
        all_failed = all(r.verdict != "pass" for r in recent)

        if all_failed:
            return GuardResult(
                guard_name="resource",
                verdict=GuardVerdict.WARN,
                confidence=0.7,
                message=f"Circuit breaker: {self.circuit_breaker_threshold} consecutive failures",
                risk_attribution=RiskAttribution(
                    risk_source="resource_exhaustion",
                    failure_mode="repeated_failure",
                    real_world_harm="cost_overrun",
                    confidence=0.7,
                    reasoning=f"Last {self.circuit_breaker_threshold} tool calls all resulted in non-pass verdicts",
                ),
            )

        return None


# ---------------------------------------------------------------------------
# ResourceGuard
# ---------------------------------------------------------------------------


class ResourceGuard(AIGuardBase):
    """Rules + AI guard detecting infinite loops and resource exhaustion.

    SLM template for behavioral anomaly detection (future).
    """

    name = "resource"
    primary_strategy = "rules"

    slm_prompt_template = """Analyze this agent's recent tool call pattern for behavioral anomalies:

Tool call history: {tool_call_history}
Current iteration: {iteration_count}

Is this agent:
1. Stuck in a loop (repeating the same action without progress)
2. Exhibiting erratic behavior (random tool calls with no coherent plan)
3. Making progress toward its goal

Return JSON:
{{"verdict": "safe" | "suspicious" | "malicious", "confidence": 0.0-1.0, "risk_source": "infinite_loop" | "behavioral_anomaly" | "none", "reasoning": "..."}}"""

    llm_prompt_template = None

    def __init__(
        self,
        max_iterations: int = _DEFAULT_MAX_ITERATIONS,
        max_api_calls: int = _DEFAULT_MAX_API_CALLS,
        circuit_breaker_threshold: int = _DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
    ) -> None:
        self.rule_fallback = ResourceGuardRuleChecker(
            max_iterations=max_iterations,
            max_api_calls=max_api_calls,
            circuit_breaker_threshold=circuit_breaker_threshold,
        )
