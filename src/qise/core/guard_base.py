"""Guard base classes: RuleChecker and AIGuardBase.

The three-layer decision flow (rule fast-path → SLM → LLM → rule fallback)
implements the "never fail-open" principle described in docs/architecture.md.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Literal

from qise.core.models import (
    GuardContext,
    GuardResult,
    GuardVerdict,
    ModelUnavailableError,
    RiskAttribution,
)

if TYPE_CHECKING:
    from qise.models.router import ModelRouter


# ---------------------------------------------------------------------------
# RuleChecker — deterministic rule fallback
# ---------------------------------------------------------------------------


class RuleChecker(ABC):
    """Base class for deterministic rule checks.

    Subclass this to implement rule-only guards (e.g., FilesystemGuard,
    NetworkGuard, CredentialGuard) or rule fallbacks for AI-first guards.
    """

    @abstractmethod
    def check(self, context: GuardContext) -> GuardResult:
        """Run deterministic check. Return PASS or BLOCK for definite results."""

    def check_safe_default(self, context: GuardContext) -> GuardResult:
        """Conservative default when models are unavailable.

        Override to customize, but the default is WARN (safe but not blocking).
        Never return PASS from this method — we are uncertain.
        """
        return GuardResult(
            guard_name=self.__class__.__name__,
            verdict=GuardVerdict.WARN,
            confidence=0.5,
            message="Security models unavailable, applying safe defaults",
        )


# ---------------------------------------------------------------------------
# AIGuardBase — AI-first guard with three-layer decision
# ---------------------------------------------------------------------------


class AIGuardBase(ABC):
    """Base class for all guards.

    Even rule-only guards inherit from this (set primary_strategy="rules").

    Three-layer decision flow:
        Layer 0: Rule fast-path (0ms) — deterministic BLOCK/PASS shortcuts
        Layer 1: SLM fast-screen (<50ms) — quick risk classification
        Layer 2: LLM deep analysis (<2s) — full trajectory reasoning
        Layer 3: Rule fallback — never fail-open
    """

    name: str = ""
    primary_strategy: Literal["ai", "rules"] = "ai"
    slm_prompt_template: str = ""
    llm_prompt_template: str | None = None
    rule_fallback: RuleChecker | None = None
    slm_confidence_threshold: float = 0.7

    # Set by Shield during initialization
    _model_router: ModelRouter | None = None
    _example_loader: Any | None = None

    def set_model_router(self, router: ModelRouter) -> None:
        """Inject the shared ModelRouter instance."""
        self._model_router = router

    def set_example_loader(self, loader: Any) -> None:
        """Inject the PromptExampleLoader for dynamic few-shot examples."""
        self._example_loader = loader

    def set_metrics(self, metrics: Any) -> None:
        """Inject the GuardMetrics instance for recording check results."""
        self._metrics = metrics

    def check(self, context: GuardContext) -> GuardResult:
        """Three-layer decision: rule fast-path → SLM → LLM → rule fallback.

        Key principle: SLM can ESCALATE a rule verdict but never DOWNGRADE it.
        If rules return BLOCK, that's final. If rules return WARN from a
        hard-coded pattern, SLM can override to PASS (the pattern may be
        overly conservative). But if rules return WARN from a trust boundary
        isolation (low confidence), SLM can override it since SLM provides
        actual content analysis.

        In practice: rule WARN with confidence < 0.65 can be overridden by
        SLM PASS (trust boundary isolation is a precaution, not a finding).
        Rule WARN with confidence >= 0.65 cannot be overridden.
        """
        start = time.monotonic()
        result = self._check_impl(context)
        # Record metrics if available
        if hasattr(self, "_metrics") and self._metrics is not None:
            self._metrics.record_guard_check(
                self.name, str(result.verdict), result.latency_ms,
            )
        return result

    def _check_impl(self, context: GuardContext) -> GuardResult:
        """Internal implementation of three-layer decision flow."""
        start = time.monotonic()
        # Layer 0: Deterministic rule fast-path (0ms overhead)
        rule_warn: GuardResult | None = None
        if self.rule_fallback is not None:
            rule_result = self.rule_fallback.check(context)
            # Rule BLOCK always short-circuits (definitive block)
            if rule_result.verdict == GuardVerdict.BLOCK:
                rule_result.latency_ms = _elapsed_ms(start)
                return rule_result
            # For rule-only guards, rule PASS also short-circuits
            # For AI-first guards, rule PASS does NOT short-circuit — SLM gets
            # final say (rules may miss semantic attacks like base64 exfil)
            if rule_result.verdict == GuardVerdict.PASS and self.primary_strategy == "rules":
                rule_result.latency_ms = _elapsed_ms(start)
                return rule_result
            # Save WARN result — SLM may or may not be able to downgrade
            if rule_result.verdict == GuardVerdict.WARN:
                rule_warn = rule_result

        # For rule-only guards, stop here after rule fast-path
        if self.primary_strategy == "rules":
            if self.rule_fallback is not None:
                result = self.rule_fallback.check_safe_default(context)
                result.latency_ms = _elapsed_ms(start)
                return result
            return GuardResult(
                guard_name=self.name,
                verdict=GuardVerdict.PASS,
                latency_ms=_elapsed_ms(start),
            )

        # Layer 1: SLM fast-screen (<50ms)
        try:
            slm_result = self._slm_check(context)
            if slm_result.confidence >= self.slm_confidence_threshold:
                if slm_result.verdict != GuardVerdict.ESCALATE:
                    slm_result.latency_ms = _elapsed_ms(start)
                    # SLM cannot downgrade a high-confidence rule WARN to PASS.
                    # Low-confidence rule WARNs (trust boundary isolation, < 0.65)
                    # can be overridden since SLM provides actual content analysis.
                    if rule_warn is not None and slm_result.verdict == GuardVerdict.PASS:
                        if rule_warn.confidence >= 0.65:
                            return rule_warn
                    return slm_result
                # ESCALATE → fall through to LLM
        except ModelUnavailableError:
            pass  # Degrade to LLM or rule fallback

        # Layer 2: LLM deep analysis (<2s)
        if self.llm_prompt_template:
            try:
                llm_result = self._llm_check(context)
                llm_result.latency_ms = _elapsed_ms(start)
                return llm_result
            except ModelUnavailableError:
                pass  # Fall through to rule fallback

        # Layer 3: Rule fallback (never fail-open)
        # Re-run rule check — if rules can give a definitive answer, use it.
        # Only fall to check_safe_default() when rules are also uncertain.
        if self.rule_fallback is not None:
            rule_result = self.rule_fallback.check(context)
            if rule_result.verdict in (GuardVerdict.BLOCK, GuardVerdict.PASS):
                rule_result.latency_ms = _elapsed_ms(start)
                return rule_result
            # Rules are uncertain → conservative WARN
            result = self.rule_fallback.check_safe_default(context)
            result.latency_ms = _elapsed_ms(start)
            return result

        return GuardResult(
            guard_name=self.name,
            verdict=GuardVerdict.WARN,
            confidence=0.5,
            message="Security models unavailable, applying safe defaults",
            latency_ms=_elapsed_ms(start),
        )

    def _slm_check(self, context: GuardContext) -> GuardResult:
        """SLM fast-screen stub.

        Constructs prompt from slm_prompt_template, calls ModelRouter.slm_check(),
        and parses the model response into a GuardResult.

        Expected SLM output format (JSON):
            {
                "verdict": "safe" | "suspicious" | "malicious",
                "confidence": 0.0-1.0,
                "risk_source": "...",
                "reasoning": "..."
            }

        Requires: A local SLM (≤4B params) deployed with an OpenAI-compatible
        API endpoint, e.g., AgentDoG-Qwen3-4B via vLLM or Ollama.
        Target latency: <50ms.
        """
        if self._model_router is None:
            raise ModelUnavailableError("ModelRouter not configured")

        prompt = self._render_prompt(self.slm_prompt_template, context)
        response = self._model_router.slm_check_sync(prompt)
        return self._parse_model_response(response, model_tag="slm")

    def _llm_check(self, context: GuardContext) -> GuardResult:
        """LLM deep analysis stub.

        Constructs prompt from llm_prompt_template with full trajectory,
        calls ModelRouter.llm_deep_analysis(), and parses into GuardResult
        with structured RiskAttribution.

        Expected LLM output format (JSON):
            {
                "verdict": "safe" | "suspicious" | "malicious",
                "confidence": 0.0-1.0,
                "risk_attribution": {
                    "risk_source": "...",
                    "failure_mode": "...",
                    "real_world_harm": "...",
                    "confidence": 0.0-1.0,
                    "reasoning": "..."
                }
            }

        Requires: A larger LLM (8B-70B params) via cloud API or local deployment,
        e.g., Claude Sonnet, GPT-4o-mini, Qwen2.5-72B.
        Target latency: <2s.
        """
        if self._model_router is None:
            raise ModelUnavailableError("ModelRouter not configured")

        if not self.llm_prompt_template:
            raise ModelUnavailableError("No LLM prompt template configured")

        prompt = self._render_prompt(self.llm_prompt_template, context)
        trajectory = context.session_trajectory
        response = self._model_router.llm_deep_analysis_sync(prompt, trajectory)
        return self._parse_model_response(response, model_tag="llm")

    def _render_prompt(self, template: str, context: GuardContext) -> str:
        """Render a prompt template with context variables.

        If the template already contains a '## Examples' section (hardcoded
        few-shot), dynamic examples are NOT appended to avoid duplication.
        Otherwise, dynamic few-shot examples from the YAML library are injected.
        """
        active_security_rules = "\n".join(context.active_security_rules) if context.active_security_rules else "None"
        rendered = template.format(
            tool_name=context.tool_name,
            tool_args=context.tool_args,
            trust_boundary=context.trust_boundary or "unknown",
            trust_level=context.trust_level(),
            session_trajectory=context.session_trajectory,
            tool_call_history=context.tool_call_history,
            iteration_count=context.iteration_count,
            tool_description=context.tool_description or "",
            tool_source=context.tool_source or "",
            agent_reasoning=context.agent_reasoning or "",
            workspace_path=context.workspace_path or "",
            session_id=context.session_id or "",
            user_id=context.user_id or "",
            integration_mode=context.integration_mode,
            active_security_rules=active_security_rules,
        )

        # Inject dynamic few-shot examples if template doesn't already have them
        if "## Examples" not in rendered and self._example_loader is not None:
            try:
                # SLM: max 2+2 examples; LLM: max 4+4
                is_llm = template is self.llm_prompt_template
                max_pos = 4 if is_llm else 2
                max_neg = 4 if is_llm else 2
                examples = self._example_loader.render_examples(
                    self.name, max_positive=max_pos, max_negative=max_neg,
                )
                if examples:
                    rendered = rendered.rstrip() + "\n\n## Dynamic Examples\n\n" + examples
            except Exception:
                pass  # Non-critical: examples are optional enhancement

        return rendered

    def _parse_model_response(
        self, response: Any, model_tag: str = "unknown"
    ) -> GuardResult:
        """Parse a model response dict into a GuardResult.

        The response dict is expected to have:
            verdict: "safe" | "suspicious" | "malicious"
            confidence: float
            risk_source: str (optional)
            reasoning: str (optional)
            risk_attribution: dict (optional, for LLM responses)

        Handles common SLM issues:
          - Markdown-wrapped JSON (```json ... ```)
          - Verdict synonyms (e.g., "dangerous" → "malicious")
          - Confidence out of range (clamped to 0.0-1.0)
        """
        # If response is a string, try to extract JSON from it
        if isinstance(response, str):
            response = self._extract_json_from_text(response)

        if not isinstance(response, dict):
            return GuardResult(
                guard_name=self.name,
                verdict=GuardVerdict.WARN,
                confidence=0.3,
                message=f"Unexpected model response type: {type(response)}",
                model_used=model_tag,
            )

        raw_verdict = response.get("verdict", "safe")

        # Normalize common verdict synonyms
        verdict_synonyms: dict[str, str] = {
            "dangerous": "malicious",
            "harmful": "malicious",
            "unsafe": "malicious",
            "bad": "malicious",
            "benign": "safe",
            "clean": "safe",
            "ok": "safe",
            "normal": "safe",
            "warning": "suspicious",
            "concerned": "suspicious",
            "alarmed": "malicious",
        }
        normalized = verdict_synonyms.get(raw_verdict.lower(), raw_verdict.lower())

        verdict_map = {
            "safe": GuardVerdict.PASS,
            "suspicious": GuardVerdict.WARN,
            "malicious": GuardVerdict.BLOCK,
        }
        verdict = verdict_map.get(normalized, GuardVerdict.WARN)

        # Clamp confidence to [0.0, 1.0]
        try:
            confidence = float(response.get("confidence", 0.5))
            if confidence > 1.0:
                confidence = confidence / 10.0  # Handle 1-10 scale
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.5

        reasoning = response.get("reasoning", "")

        risk_attribution: RiskAttribution | None = None
        ra_data = response.get("risk_attribution")
        if isinstance(ra_data, dict):
            risk_attribution = RiskAttribution(
                risk_source=ra_data.get("risk_source", response.get("risk_source", "unknown")),
                failure_mode=ra_data.get("failure_mode", "unknown"),
                real_world_harm=ra_data.get("real_world_harm", "unknown"),
                confidence=ra_data.get("confidence", confidence),
                reasoning=ra_data.get("reasoning", reasoning),
            )

        message = reasoning or f"Model ({model_tag}) assessed as {raw_verdict}"

        return GuardResult(
            guard_name=self.name,
            verdict=verdict,
            confidence=confidence,
            message=message,
            risk_attribution=risk_attribution,
            model_used=model_tag,
        )

    @staticmethod
    def _extract_json_from_text(text: str) -> Any:
        """Extract JSON from text that may contain markdown wrapping.

        Handles:
          - ```json ... ``` markdown code blocks
          - Bare JSON objects
          - Leading/trailing whitespace and text
        """
        import json
        import re

        text = text.strip()

        # Try markdown code block first
        md_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
        if md_match:
            try:
                return json.loads(md_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Try to find a JSON object in the text
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        return text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _elapsed_ms(start: float) -> int:
    """Return elapsed time in milliseconds since *start*."""
    return int((time.monotonic() - start) * 1000)
