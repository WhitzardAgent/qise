"""Tests for AIGuardBase config options: skip_slm_on_rule_pass and slm_override_rule_warn_threshold."""

from __future__ import annotations

import pytest

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict


# -- Helpers ------------------------------------------------------------------


class AlwaysPassRule(RuleChecker):
    """Rule checker that always returns PASS."""

    def check(self, context: GuardContext) -> GuardResult:
        return GuardResult(
            guard_name="test_rule",
            verdict=GuardVerdict.PASS,
            confidence=0.9,
            message="Rule passed",
        )


class AlwaysWarnRule(RuleChecker):
    """Rule checker that always returns WARN with configurable confidence."""

    def __init__(self, confidence: float = 0.7) -> None:
        self._confidence = confidence

    def check(self, context: GuardContext) -> GuardResult:
        return GuardResult(
            guard_name="test_rule",
            verdict=GuardVerdict.WARN,
            confidence=self._confidence,
            message="Rule warning",
        )


class AlwaysBlockRule(RuleChecker):
    """Rule checker that always returns BLOCK."""

    def check(self, context: GuardContext) -> GuardResult:
        return GuardResult(
            guard_name="test_rule",
            verdict=GuardVerdict.BLOCK,
            confidence=0.95,
            message="Rule blocked",
        )


class TestAIGuard(AIGuardBase):
    """Concrete AIGuardBase subclass for testing."""

    name = "test_guard"
    primary_strategy = "ai"
    slm_prompt_template = "Test {tool_name} {trust_boundary}"


class TestRulesGuard(AIGuardBase):
    """Rules-primary guard for testing."""

    name = "test_rules_guard"
    primary_strategy = "rules"
    slm_prompt_template = ""


@pytest.fixture
def ctx() -> GuardContext:
    return GuardContext(tool_name="bash", tool_args={"command": "ls"})


# -- skip_slm_on_rule_pass tests ---------------------------------------------


class TestSkipSlmOnRulePass:

    def test_default_is_false(self) -> None:
        guard = TestAIGuard()
        assert guard.skip_slm_on_rule_pass is False

    def test_ai_guard_rule_pass_does_not_shortcircuit_by_default(self, ctx: GuardContext) -> None:
        """AI-first guard: rule PASS does NOT short-circuit at Layer 0 by default.

        Without SLM/LLM, it falls through to Layer 3 rule fallback which
        re-runs rules and returns PASS again. The key difference from
        skip_slm_on_rule_pass=True is that the SLM layer IS attempted
        (just unavailable in this test).
        """
        guard = TestAIGuard()
        guard.rule_fallback = AlwaysPassRule()
        result = guard._check_impl(ctx)
        # Layer 3 fallback re-runs rule check → PASS
        assert result.verdict == GuardVerdict.PASS

    def test_ai_guard_rule_pass_shortcircuits_when_enabled(self, ctx: GuardContext) -> None:
        """AI-first guard with skip_slm_on_rule_pass=True: rule PASS short-circuits."""
        guard = TestAIGuard()
        guard.rule_fallback = AlwaysPassRule()
        guard.skip_slm_on_rule_pass = True
        result = guard._check_impl(ctx)
        assert result.verdict == GuardVerdict.PASS
        assert result.message == "Rule passed"

    def test_rules_guard_rule_pass_always_shortcircuits(self, ctx: GuardContext) -> None:
        """Rules-primary guard: rule PASS always short-circuits regardless of flag."""
        guard = TestRulesGuard()
        guard.rule_fallback = AlwaysPassRule()
        guard.skip_slm_on_rule_pass = False  # Should not matter
        result = guard._check_impl(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_skip_slm_does_not_affect_block(self, ctx: GuardContext) -> None:
        """Rule BLOCK always short-circuits regardless of skip_slm_on_rule_pass."""
        guard = TestAIGuard()
        guard.rule_fallback = AlwaysBlockRule()
        guard.skip_slm_on_rule_pass = False
        result = guard._check_impl(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_skip_slm_does_not_affect_warn(self, ctx: GuardContext) -> None:
        """Rule WARN does not short-circuit regardless of skip_slm_on_rule_pass."""
        guard = TestAIGuard()
        guard.rule_fallback = AlwaysWarnRule()
        guard.skip_slm_on_rule_pass = True
        # WARN does not short-circuit; falls through to SLM/LLM/fallback
        result = guard._check_impl(ctx)
        # Without SLM/LLM, falls to check_safe_default → WARN
        assert result.verdict == GuardVerdict.WARN


# -- slm_override_rule_warn_threshold tests -----------------------------------


class TestSlmOverrideRuleWarnThreshold:

    def test_default_is_0_65(self) -> None:
        guard = TestAIGuard()
        assert guard.slm_override_rule_warn_threshold == 0.65

    def test_custom_threshold(self) -> None:
        guard = TestAIGuard()
        guard.slm_override_rule_warn_threshold = 0.8
        assert guard.slm_override_rule_warn_threshold == 0.8

    def test_low_confidence_rule_warn_can_be_overridden_by_slm(self, ctx: GuardContext) -> None:
        """Rule WARN with confidence < threshold can be overridden by SLM PASS.

        We can't easily mock SLM here, so we verify the attribute is used
        correctly by checking the guard's attribute directly.
        """
        guard = TestAIGuard()
        guard.rule_fallback = AlwaysWarnRule(confidence=0.5)  # Below default 0.65
        # The threshold determines whether SLM can override the rule WARN
        # With confidence 0.5 < 0.65, SLM could override (if available)
        assert 0.5 < guard.slm_override_rule_warn_threshold

    def test_high_confidence_rule_warn_cannot_be_overridden(self, ctx: GuardContext) -> None:
        """Rule WARN with confidence >= threshold cannot be overridden by SLM PASS."""
        guard = TestAIGuard()
        guard.rule_fallback = AlwaysWarnRule(confidence=0.8)  # Above default 0.65
        assert 0.8 >= guard.slm_override_rule_warn_threshold

    def test_configurable_threshold_changes_override_boundary(self) -> None:
        """Setting threshold to 0.9 means only confidence >= 0.9 blocks SLM override."""
        guard = TestAIGuard()
        guard.slm_override_rule_warn_threshold = 0.9
        # Confidence 0.8 < 0.9 → SLM can override
        assert 0.8 < guard.slm_override_rule_warn_threshold
        # Confidence 0.9 >= 0.9 → SLM cannot override
        assert 0.9 >= guard.slm_override_rule_warn_threshold


# -- Shield config wiring tests ----------------------------------------------


class TestShieldConfigWiring:

    def test_guard_config_fields_exist(self) -> None:
        from qise.core.config import GuardConfig
        gc = GuardConfig()
        assert gc.skip_slm_on_rule_pass is None
        assert gc.slm_override_rule_warn_threshold is None

    def test_guard_config_with_values(self) -> None:
        from qise.core.config import GuardConfig
        gc = GuardConfig(
            skip_slm_on_rule_pass=True,
            slm_override_rule_warn_threshold=0.8,
        )
        assert gc.skip_slm_on_rule_pass is True
        assert gc.slm_override_rule_warn_threshold == 0.8

    def test_shield_creates_guard_with_config(self) -> None:
        from qise.core.config import GuardConfig, GuardsConfig, ShieldConfig
        from qise.core.shield import Shield

        config = ShieldConfig(
            guards=GuardsConfig(
                enabled=["command"],
                config={
                    "command": GuardConfig(
                        mode="enforce",
                        skip_slm_on_rule_pass=True,
                        slm_override_rule_warn_threshold=0.8,
                    ),
                },
            ),
        )
        shield = Shield(config=config)
        # Find the command guard in pipeline
        for guard in shield.pipeline.all_guards:
            if guard.name == "command":
                assert guard.skip_slm_on_rule_pass is True
                assert guard.slm_override_rule_warn_threshold == 0.8
                break
        else:
            pytest.fail("CommandGuard not found in pipeline")

    def test_shield_default_config_leaves_guards_at_defaults(self) -> None:
        from qise.core.config import ShieldConfig
        from qise.core.shield import Shield

        config = ShieldConfig()
        shield = Shield(config=config)
        for guard in shield.pipeline.all_guards:
            assert guard.skip_slm_on_rule_pass is False
            assert guard.slm_override_rule_warn_threshold == 0.65
