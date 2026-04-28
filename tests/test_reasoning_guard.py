"""Tests for ReasoningGuard."""

from qise.core.models import GuardContext, GuardVerdict
from qise.guards.reasoning import ReasoningGuard, THRESHOLD_ADJUSTMENTS, SAFETY_REMINDERS


class TestReasoningGuardNoReasoning:

    def test_no_reasoning_passes(self) -> None:
        guard = ReasoningGuard()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_none_reasoning_passes(self) -> None:
        guard = ReasoningGuard()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"}, agent_reasoning=None)
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_empty_reasoning_passes(self) -> None:
        guard = ReasoningGuard()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"}, agent_reasoning="")
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestReasoningGuardModelUnavailable:

    def test_model_unavailable_warns(self) -> None:
        guard = ReasoningGuard()
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            agent_reasoning="I need to list the files in this directory.",
        )
        result = guard.check(ctx)
        # SLM is unavailable (stub raises ModelUnavailableError), should WARN
        assert result.verdict == GuardVerdict.WARN
        assert "unavailable" in result.message.lower()

    def test_model_unavailable_no_threshold_adjustments(self) -> None:
        guard = ReasoningGuard()
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            agent_reasoning="Some reasoning here.",
        )
        result = guard.check(ctx)
        # When model unavailable, no threshold adjustments
        assert result.threshold_adjustments is None


class TestReasoningGuardThresholdAdjustments:

    def test_threshold_adjustments_defined(self) -> None:
        assert "exfil_intent" in THRESHOLD_ADJUSTMENTS
        assert "bypass_intent" in THRESHOLD_ADJUSTMENTS
        assert "privilege_escalation" in THRESHOLD_ADJUSTMENTS
        assert "injection_compliance" in THRESHOLD_ADJUSTMENTS

    def test_exfil_adjusts_exfil_guard(self) -> None:
        adjustments = THRESHOLD_ADJUSTMENTS["exfil_intent"]
        assert "exfil" in adjustments
        assert adjustments["exfil"] < 0  # Threshold goes down (more sensitive)

    def test_bypass_adjusts_command_guard(self) -> None:
        adjustments = THRESHOLD_ADJUSTMENTS["bypass_intent"]
        assert "command" in adjustments
        assert adjustments["command"] < 0

    def test_privilege_escalation_adjusts_command(self) -> None:
        adjustments = THRESHOLD_ADJUSTMENTS["privilege_escalation"]
        assert "command" in adjustments
        assert adjustments["command"] < 0

    def test_injection_compliance_adjusts_prompt(self) -> None:
        adjustments = THRESHOLD_ADJUSTMENTS["injection_compliance"]
        assert "prompt" in adjustments
        assert adjustments["prompt"] < 0


class TestReasoningGuardSafetyReminders:

    def test_safety_reminders_defined(self) -> None:
        assert "exfil_intent" in SAFETY_REMINDERS
        assert "bypass_intent" in SAFETY_REMINDERS
        assert "privilege_escalation" in SAFETY_REMINDERS
        assert "injection_compliance" in SAFETY_REMINDERS

    def test_safety_reminders_are_prefixed(self) -> None:
        for key, reminder in SAFETY_REMINDERS.items():
            assert reminder.startswith("[Security]"), f"Reminder for {key} missing [Security] prefix"

    def test_safety_reminders_non_empty(self) -> None:
        for key, reminder in SAFETY_REMINDERS.items():
            assert len(reminder) > 20, f"Reminder for {key} seems too short"


class TestReasoningGuardProcessResult:

    def test_process_slm_pass(self) -> None:
        guard = ReasoningGuard()
        from qise.core.models import GuardResult
        pass_result = GuardResult(
            guard_name="reasoning",
            verdict=GuardVerdict.PASS,
            confidence=0.9,
            message="No issues detected",
        )
        processed = guard._process_slm_result(pass_result)
        assert processed.verdict == GuardVerdict.PASS

    def test_process_slm_warn_with_risk_source(self) -> None:
        guard = ReasoningGuard()
        from qise.core.models import GuardResult, RiskAttribution
        warn_result = GuardResult(
            guard_name="reasoning",
            verdict=GuardVerdict.WARN,
            confidence=0.7,
            message="Potential exfiltration intent detected",
            risk_attribution=RiskAttribution(
                risk_source="exfil_intent",
                failure_mode="data_leakage",
                real_world_harm="privacy_violation",
                confidence=0.7,
                reasoning="Agent reasoning mentions extracting data",
            ),
        )
        processed = guard._process_slm_result(warn_result)
        assert processed.verdict == GuardVerdict.WARN
        assert processed.threshold_adjustments is not None
        assert "exfil" in processed.threshold_adjustments

    def test_process_slm_warn_infers_from_message(self) -> None:
        guard = ReasoningGuard()
        from qise.core.models import GuardResult
        warn_result = GuardResult(
            guard_name="reasoning",
            verdict=GuardVerdict.WARN,
            confidence=0.6,
            message="Detected bypass_intent in reasoning",
        )
        processed = guard._process_slm_result(warn_result)
        assert processed.threshold_adjustments is not None
        assert "command" in processed.threshold_adjustments


class TestReasoningGuardNeverBlocks:

    def test_guard_name_is_reasoning(self) -> None:
        guard = ReasoningGuard()
        assert guard.name == "reasoning"

    def test_primary_strategy_is_ai(self) -> None:
        guard = ReasoningGuard()
        assert guard.primary_strategy == "ai"

    def test_no_rule_fallback(self) -> None:
        guard = ReasoningGuard()
        assert guard.rule_fallback is None
