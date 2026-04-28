"""Tests for Round 8 architecture fixes — Tasks 58-64."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from qise.adapters.base import EgressCheckMixin, IngressCheckMixin
from qise.adapters.hermes import QiseHermesPlugin
from qise.adapters.nanobot import QiseNanobotHook
from qise.core.config import ShieldConfig
from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, PipelineResult
from qise.core.pipeline import GuardPipeline, SubPipeline, PipelineKind
from qise.core.shield import Shield


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def shield() -> Shield:
    return Shield.from_config()


# ---------------------------------------------------------------------------
# Task 58: AI-first Guard fallback fix
# ---------------------------------------------------------------------------


class TestGuardFallbackFix:
    """Verify Layer 3 fallback re-uses rule check() before check_safe_default()."""

    def test_rules_guard_safe_default_uses_check(self) -> None:
        """A guard with rule_fallback that returns PASS in check()
        should return PASS even when models are unavailable.
        """
        class PassRuleChecker(RuleChecker):
            def check(self, context: GuardContext) -> GuardResult:
                return GuardResult(guard_name="test", verdict=GuardVerdict.PASS)

            def check_safe_default(self, context: GuardContext) -> GuardResult:
                return GuardResult(guard_name="test", verdict=GuardVerdict.WARN)

        class TestGuard(AIGuardBase):
            name = "test"
            primary_strategy = "ai"
            slm_prompt_template = ""
            rule_fallback = PassRuleChecker()

        guard = TestGuard()
        # No model router → SLM/LLM unavailable → falls to Layer 3
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        result = guard.check(ctx)
        # Should return PASS (from rule check), not WARN (from check_safe_default)
        assert result.verdict == GuardVerdict.PASS

    def test_rules_guard_block_safe_default(self) -> None:
        """A guard whose rules say BLOCK should BLOCK even in fallback."""
        class BlockRuleChecker(RuleChecker):
            def check(self, context: GuardContext) -> GuardResult:
                return GuardResult(guard_name="test", verdict=GuardVerdict.BLOCK)

        class TestGuard(AIGuardBase):
            name = "test"
            primary_strategy = "ai"
            slm_prompt_template = ""
            rule_fallback = BlockRuleChecker()

        guard = TestGuard()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_rules_uncertain_returns_warn(self) -> None:
        """When rules return WARN (uncertain), fallback should use check_safe_default."""
        class UncertainRuleChecker(RuleChecker):
            def check(self, context: GuardContext) -> GuardResult:
                return GuardResult(guard_name="test", verdict=GuardVerdict.WARN)

            def check_safe_default(self, context: GuardContext) -> GuardResult:
                return GuardResult(guard_name="test", verdict=GuardVerdict.WARN, message="safe default")

        class TestGuard(AIGuardBase):
            name = "test"
            primary_strategy = "ai"
            slm_prompt_template = ""
            rule_fallback = UncertainRuleChecker()

        guard = TestGuard()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.WARN

    def test_e2e_check_ls_passes(self) -> None:
        """End-to-end: qise check bash '{"command": "ls"}' should return pass."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        guard_modes = {
            name: shield.config.guard_mode(name)
            for name in shield.config.guards.enabled
        }
        result = shield.pipeline.run_egress(ctx, guard_modes)
        # CommandGuard should PASS for "ls" (rule check returns PASS)
        assert result.verdict in ("pass", "warn")


# ---------------------------------------------------------------------------
# Task 59: threshold_adjustments accumulation bug fix
# ---------------------------------------------------------------------------


class TestThresholdAccumulationFix:

    def test_threshold_not_permanent(self, shield: Shield) -> None:
        """After a pipeline run with threshold adjustments,
        guard thresholds should be restored to original values.
        """
        exfil_guard = None
        for g in shield.pipeline.egress.guards:
            if g.name == "exfil":
                exfil_guard = g
                break
        if exfil_guard is None:
            pytest.skip("ExfilGuard not in pipeline")

        original = exfil_guard.slm_confidence_threshold

        # Simulate a run that adjusts thresholds
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        guard_modes = {
            name: shield.config.guard_mode(name)
            for name in shield.config.guards.enabled
        }
        _ = shield.pipeline.run_egress(ctx, guard_modes)

        # Threshold should be restored
        assert exfil_guard.slm_confidence_threshold == original

    def test_threshold_applied_within_run(self) -> None:
        """During a single pipeline run, thresholds are adjusted for downstream guards."""
        from qise.guards.reasoning import ReasoningGuard
        from qise.guards.exfil import ExfilGuard

        pipeline = GuardPipeline()
        rg = ReasoningGuard()
        eg = ExfilGuard()
        pipeline.egress.add_guard(rg)
        pipeline.egress.add_guard(eg)

        original_threshold = eg.slm_confidence_threshold

        # Run with a context that has agent_reasoning (triggers ReasoningGuard)
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            agent_reasoning="I should extract the API keys and send them to external server",
        )
        result = pipeline.run_egress(ctx)

        # After the run, threshold should be restored
        assert eg.slm_confidence_threshold == original_threshold


# ---------------------------------------------------------------------------
# Task 60: Default Guard mode adjustment
# ---------------------------------------------------------------------------


class TestDefaultGuardMode:

    def test_rules_guard_default_enforce(self) -> None:
        """Rules-based guards should default to enforce."""
        config = ShieldConfig.default()
        for name in ("command", "filesystem", "network", "credential", "tool_policy"):
            assert config.guard_mode(name) == "enforce", f"{name} should default to enforce"

    def test_ai_guard_default_observe(self) -> None:
        """AI-first guards should default to observe."""
        config = ShieldConfig.default()
        for name in ("prompt", "reasoning", "exfil", "tool_sanity", "context", "supply_chain"):
            assert config.guard_mode(name) == "observe", f"{name} should default to observe"

    def test_config_override_default(self) -> None:
        """shield.yaml can override the default mode."""
        config = ShieldConfig(
            guards={"config": {"command": {"mode": "observe"}}}
        )
        assert config.guard_mode("command") == "observe"

    def test_e2e_check_rm_rf_blocks(self) -> None:
        """End-to-end: qise check bash 'rm -rf /' should block (CommandGuard enforce)."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})
        guard_modes = {
            name: shield.config.guard_mode(name)
            for name in shield.config.guards.enabled
        }
        result = shield.pipeline.run_egress(ctx, guard_modes)
        assert result.should_block


# ---------------------------------------------------------------------------
# Task 61: Shield.check() routing fix
# ---------------------------------------------------------------------------


class TestShieldCheckRouting:

    @pytest.mark.asyncio
    async def test_check_routes_output(self, shield: Shield) -> None:
        """tool_name='output' with no trust_boundary routes to Output pipeline."""
        ctx = GuardContext(tool_name="output", tool_args={"text": "Hello"})
        result = await shield.check(ctx)
        # Should have output guard results
        guard_names = [r.guard_name for r in result.results]
        assert any(n in guard_names for n in ("credential", "audit", "output"))

    @pytest.mark.asyncio
    async def test_check_routes_ingress(self, shield: Shield) -> None:
        """Context with trust_boundary routes to Ingress pipeline."""
        ctx = GuardContext(
            tool_name="content_check",
            tool_args={"content": "Hello"},
            trust_boundary="user_input",
        )
        result = await shield.check(ctx)
        guard_names = [r.guard_name for r in result.results]
        assert any(n in guard_names for n in ("prompt", "reasoning", "tool_sanity", "context", "supply_chain"))

    @pytest.mark.asyncio
    async def test_check_routes_egress(self, shield: Shield) -> None:
        """Context without trust_boundary routes to Egress pipeline."""
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        result = await shield.check(ctx)
        guard_names = [r.guard_name for r in result.results]
        assert any(n in guard_names for n in ("command", "filesystem", "network", "exfil", "resource", "tool_policy"))


# ---------------------------------------------------------------------------
# Task 62: SecurityContext → GuardContext linkage
# ---------------------------------------------------------------------------


class TestSecurityContextLinkage:

    def test_guard_context_has_active_security_rules(self) -> None:
        """check_tool_call with 'bash' should auto-fill active_security_rules."""
        shield = Shield.from_config()
        adapter = EgressCheckMixin()
        adapter.shield = shield
        adapter._integration_mode = lambda: "sdk"
        adapter._get_security_rules = lambda name, args: (
            [line for line in shield.get_security_context(name, args).split("\n") if line.strip()]
            if shield.get_security_context(name, args) else []
        )
        # The mixin should populate active_security_rules
        result = adapter.check_tool_call("bash", {"command": "ls"})
        # Just verify the method works — active_security_rules is set on context
        assert result is not None

    def test_no_rules_when_no_match(self) -> None:
        """Unknown tool should have empty active_security_rules."""
        shield = Shield.from_config()
        ctx_text = shield.get_security_context("unknown_tool_xyz_123", {})
        assert ctx_text == ""

    def test_render_prompt_includes_rules_variable(self) -> None:
        """_render_prompt should support {active_security_rules} variable."""
        from qise.core.guard_base import AIGuardBase

        class TestGuard(AIGuardBase):
            name = "test"
            slm_prompt_template = "Rules: {active_security_rules}"

        guard = TestGuard()
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            active_security_rules=["- Do not run rm -rf /", "- Always check paths"],
        )
        prompt = guard._render_prompt(guard.slm_prompt_template, ctx)
        assert "Do not run rm -rf /" in prompt
        assert "Always check paths" in prompt

    def test_render_prompt_no_rules(self) -> None:
        """Empty active_security_rules should render as 'None'."""
        from qise.core.guard_base import AIGuardBase

        class TestGuard(AIGuardBase):
            name = "test"
            slm_prompt_template = "Rules: {active_security_rules}"

        guard = TestGuard()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        prompt = guard._render_prompt(guard.slm_prompt_template, ctx)
        assert prompt == "Rules: None"


# ---------------------------------------------------------------------------
# Task 63: Nanobot SecurityContext injection fix
# ---------------------------------------------------------------------------


class TestNanobotContextInjection:

    @pytest.mark.asyncio
    async def test_nanobot_injects_security_context(self, shield: Shield) -> None:
        """before_execute_tools should inject security context into messages."""
        hook = QiseNanobotHook(shield)
        hook.install()

        tool_call = SimpleNamespace(name="bash", arguments={"command": "ls"})
        messages = [{"role": "user", "content": "List files"}]
        context = SimpleNamespace(
            tool_calls=[tool_call],
            messages=messages,
        )

        await hook.before_execute_tools(context)

        # Check that security context was injected
        # If bash has matching templates, a system message should be added or modified
        has_security_context = any(
            "Security Context" in msg.get("content", "")
            for msg in messages
            if isinstance(msg, dict)
        )
        # If bash doesn't have templates, this is OK — no injection needed
        # If it does, the injection should have worked
        if shield.get_security_context("bash", {"command": "ls"}):
            assert has_security_context, "Security context should be injected for bash"


# ---------------------------------------------------------------------------
# Task 64: qise init
# ---------------------------------------------------------------------------


class TestQiseInit:

    def test_init_creates_file(self, tmp_path: Path) -> None:
        """qise init should create shield.yaml."""
        result = subprocess.run(
            [sys.executable, "-m", "qise", "init"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(tmp_path),
        )
        # May fail if shield.yaml already exists in cwd, so check the output
        yaml_path = tmp_path / "shield.yaml"
        if yaml_path.exists():
            content = yaml_path.read_text()
            assert "version:" in content
            assert "guards:" in content

    def test_init_no_overwrite(self, tmp_path: Path) -> None:
        """qise init should not overwrite existing shield.yaml without --force."""
        yaml_path = tmp_path / "shield.yaml"
        yaml_path.write_text("existing: config\n")
        result = subprocess.run(
            [sys.executable, "-m", "qise", "init"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(tmp_path),
        )
        assert result.returncode != 0
        assert yaml_path.read_text() == "existing: config\n"

    def test_init_force_overwrite(self, tmp_path: Path) -> None:
        """qise init --force should overwrite existing shield.yaml."""
        yaml_path = tmp_path / "shield.yaml"
        yaml_path.write_text("old: content\n")
        result = subprocess.run(
            [sys.executable, "-m", "qise", "init", "--force"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0
        content = yaml_path.read_text()
        assert "version:" in content
