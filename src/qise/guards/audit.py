"""AuditGuard — AI + rules guard for security event correlation and attack chain reconstruction.

Correlates events across a session, detects attack patterns
(info-gather→exfil, injection→exec, probe→attack), and logs
all security events.
"""

from __future__ import annotations

from typing import Any

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution


# ---------------------------------------------------------------------------
# Attack pattern definitions
# ---------------------------------------------------------------------------

# Tool names that indicate information gathering
_INFO_GATHER_TOOLS = frozenset({
    "read_file", "cat", "head", "tail", "less", "more",
    "sql_query", "database_query", "search", "grep", "find",
})

# Tool names that indicate exfiltration
_EXFIL_TOOLS = frozenset({
    "http_request", "curl", "wget", "fetch", "post",
    "send_email", "webhook", "upload",
})

# Tool names that indicate command execution
_EXEC_TOOLS = frozenset({
    "bash", "shell", "exec", "run", "command",
})

# Tool names that indicate injection source
_INJECTION_TOOLS = frozenset({
    "web_search", "web_scrape", "fetch_url", "browse",
})

# Tool names that indicate network probing
_PROBE_TOOLS = frozenset({
    "nmap", "ping", "traceroute", "nslookup", "dig",
    "port_scan", "network_scan",
})


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class AuditGuardRuleChecker(RuleChecker):
    """Security event correlation and attack pattern detection."""

    def __init__(
        self,
        session_tracker: Any | None = None,
        event_logger: Any | None = None,
    ) -> None:
        self.session_tracker = session_tracker
        self.event_logger = event_logger

    def check(self, context: GuardContext) -> GuardResult:
        # 1. Log the event
        if self.event_logger and context.session_id:
            self._log_event(context)

        # 2. Session risk score check
        risk_result = self._check_risk_score(context)
        if risk_result is not None:
            return risk_result

        # 3. Attack pattern correlation
        pattern_result = self._check_attack_patterns(context)
        if pattern_result is not None:
            return pattern_result

        return GuardResult(guard_name="audit", verdict=GuardVerdict.PASS)

    def _log_event(self, context: GuardContext) -> None:
        """Record the current check as an audit event."""
        if self.event_logger:
            self.event_logger.log_event("audit_check", {
                "tool_name": context.tool_name,
                "session_id": context.session_id,
            })

    def _check_risk_score(self, context: GuardContext) -> GuardResult | None:
        """Check session risk score from SessionTracker."""
        if not self.session_tracker or not context.session_id:
            return None

        score = self.session_tracker.get_risk_score(context.session_id)
        if score > 0.7:
            return GuardResult(
                guard_name="audit",
                verdict=GuardVerdict.WARN,
                confidence=0.8,
                message=f"Session risk score elevated: {score:.2f}",
                risk_attribution=RiskAttribution(
                    risk_source="correlated_events",
                    failure_mode="ongoing_attack",
                    real_world_harm="system_compromise",
                    confidence=0.8,
                    reasoning=f"Session has accumulated risk score of {score:.2f}",
                ),
            )
        return None

    def _check_attack_patterns(self, context: GuardContext) -> GuardResult | None:
        """Detect attack patterns in tool call history."""
        history = context.tool_call_history
        if len(history) < 2:
            return None

        current_tool = context.tool_name

        # Pattern 1: Information gathering → Exfiltration
        if current_tool in _EXFIL_TOOLS:
            for prev in history:
                if prev.tool_name in _INFO_GATHER_TOOLS:
                    return GuardResult(
                        guard_name="audit",
                        verdict=GuardVerdict.WARN,
                        confidence=0.75,
                        message="Attack pattern: information gathering followed by exfiltration attempt",
                        risk_attribution=RiskAttribution(
                            risk_source="attack_chain",
                            failure_mode="data_leakage",
                            real_world_harm="privacy_violation",
                            confidence=0.75,
                            reasoning="Data was read and then targeted for exfiltration",
                        ),
                    )

        # Pattern 2: Injection source → Dangerous command execution
        if current_tool in _EXEC_TOOLS:
            for prev in history:
                if prev.tool_name in _INJECTION_TOOLS:
                    return GuardResult(
                        guard_name="audit",
                        verdict=GuardVerdict.WARN,
                        confidence=0.75,
                        message="Attack pattern: external content followed by command execution",
                        risk_attribution=RiskAttribution(
                            risk_source="attack_chain",
                            failure_mode="unauthorized_action",
                            real_world_harm="system_compromise",
                            confidence=0.75,
                            reasoning="External content was received before executing a command",
                        ),
                    )

        # Pattern 3: Probing → Attack
        if current_tool in _EXEC_TOOLS or current_tool in _EXFIL_TOOLS:
            for prev in history:
                if prev.tool_name in _PROBE_TOOLS:
                    return GuardResult(
                        guard_name="audit",
                        verdict=GuardVerdict.WARN,
                        confidence=0.75,
                        message="Attack pattern: network probing followed by exploitation",
                        risk_attribution=RiskAttribution(
                            risk_source="attack_chain",
                            failure_mode="unauthorized_action",
                            real_world_harm="system_compromise",
                            confidence=0.75,
                            reasoning="Network scanning was performed before executing actions",
                        ),
                    )

        return None


# ---------------------------------------------------------------------------
# AuditGuard
# ---------------------------------------------------------------------------


class AuditGuard(AIGuardBase):
    """AI + rules guard for security event correlation and attack chain reconstruction.

    Tracks session risk scores and correlates tool calls to detect
    multi-step attack patterns.
    """

    name = "audit"
    primary_strategy = "rules"

    slm_prompt_template = """Analyze this sequence of tool calls for correlated attack patterns:
1. Information gathering followed by exfiltration
2. Injection followed by command execution
3. Probing followed by exploitation

Recent tool calls: {tool_call_history}

Return JSON:
{{"verdict": "safe" | "suspicious" | "malicious", "confidence": 0.0-1.0, "risk_source": "attack_chain" | "correlated_events" | "none", "reasoning": "..."}}"""

    llm_prompt_template = """Reconstruct the attack chain from this session's tool call history:

Tool call history: {tool_call_history}
Session trajectory: {session_trajectory}

Identify:
1. The initial attack vector (how the attacker gained influence)
2. The attack chain (sequence of actions building toward the goal)
3. The intended outcome (what the attacker was trying to achieve)

Return JSON:
{{"verdict": "safe" | "suspicious" | "malicious", "confidence": 0.0-1.0, "risk_attribution": {{"risk_source": "attack_chain", "failure_mode": "...", "real_world_harm": "...", "confidence": 0.0-1.0, "reasoning": "..."}}}}"""

    def __init__(
        self,
        session_tracker: Any | None = None,
        event_logger: Any | None = None,
    ) -> None:
        self.session_tracker = session_tracker
        self.event_logger = event_logger
        self.rule_fallback = AuditGuardRuleChecker(
            session_tracker=session_tracker,
            event_logger=event_logger,
        )
