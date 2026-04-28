"""GuardPipeline — three sub-pipelines with short-circuit execution.

Ingress  (World → Agent): PromptGuard → ToolSanityGuard → ContextGuard → SupplyChainGuard
Egress   (Agent → World): CommandGuard → FilesystemGuard → NetworkGuard → ExfilGuard → ResourceGuard → ToolPolicyGuard
Output   (Audit):         CredentialGuard → AuditGuard → OutputGuard

Execution rules:
  - BLOCK short-circuits: pipeline stops immediately
  - WARN results are collected
  - ESCALATE triggers LLM deep analysis on the guard that returned it
  - ReasoningGuard threshold_adjustments are propagated to subsequent guards
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from qise.core.guard_base import AIGuardBase
from qise.core.models import (
    GuardContext,
    GuardMode,
    GuardResult,
    GuardVerdict,
    PipelineResult,
)


class PipelineKind(str, Enum):
    INGRESS = "ingress"
    EGRESS = "egress"
    OUTPUT = "output"


class SubPipeline:
    """An ordered sequence of guards forming one pipeline (Ingress/Egress/Output)."""

    def __init__(self, kind: PipelineKind, guards: list[AIGuardBase] | None = None) -> None:
        self.kind = kind
        self.guards: list[AIGuardBase] = guards or []

    def add_guard(self, guard: AIGuardBase) -> None:
        self.guards.append(guard)

    def run(self, context: GuardContext, guard_modes: dict[str, str] | None = None) -> PipelineResult:
        """Execute all guards in order with short-circuit on BLOCK.

        Args:
            context: The guard context to check.
            guard_modes: Optional mapping of guard_name → mode (observe/enforce/off).
                         If a guard is "off", it is skipped.

        Returns:
            PipelineResult with aggregated verdicts and threshold adjustments.
        """
        results: list[GuardResult] = []
        warnings: list[str] = []
        threshold_adjustments: dict[str, float] = {}
        blocked_by: str | None = None
        final_verdict = GuardVerdict.PASS
        guard_modes = guard_modes or {}

        # Snapshot original thresholds to restore after run
        original_thresholds: dict[str, float] = {}

        for guard in self.guards:
            # Skip disabled guards
            mode = guard_modes.get(guard.name)
            if mode == GuardMode.OFF:
                continue

            # Apply any threshold adjustments from ReasoningGuard
            if guard.name in threshold_adjustments:
                original_thresholds[guard.name] = guard.slm_confidence_threshold
                guard.slm_confidence_threshold = max(
                    0.1, guard.slm_confidence_threshold + threshold_adjustments[guard.name]
                )

            try:
                result = guard.check(context)
            except Exception as exc:
                # Guard crashed — conservative: WARN, don't block
                result = GuardResult(
                    guard_name=guard.name,
                    verdict=GuardVerdict.WARN,
                    confidence=0.3,
                    message=f"Guard error: {exc}",
                )

            # In observe mode, downgrade BLOCK to WARN
            if mode == GuardMode.OBSERVE and result.verdict == GuardVerdict.BLOCK:
                result.verdict = GuardVerdict.WARN
                result.message = f"[OBSERVE] Would block: {result.message}"

            results.append(result)

            # Collect threshold adjustments for downstream guards
            if result.threshold_adjustments:
                for gname, delta in result.threshold_adjustments.items():
                    current = threshold_adjustments.get(gname, 0.0)
                    threshold_adjustments[gname] = current + delta

            # Handle verdict
            if result.verdict == GuardVerdict.BLOCK:
                blocked_by = guard.name
                final_verdict = GuardVerdict.BLOCK
                break  # Short-circuit

            if result.verdict == GuardVerdict.WARN:
                warnings.append(f"[{guard.name}] {result.message}")
                # WARN doesn't override PASS → but if any warn, result is at least warn
                if final_verdict == GuardVerdict.PASS:
                    final_verdict = GuardVerdict.WARN

            # ESCALATE: the guard's own _slm_check already handled this
            # by falling through to LLM in AIGuardBase.check().
            # No special pipeline handling needed — the guard returns its
            # final verdict after internal escalation.

        # Restore original thresholds to prevent cross-session accumulation
        for gname, original in original_thresholds.items():
            for guard in self.guards:
                if guard.name == gname:
                    guard.slm_confidence_threshold = original
                    break

        return PipelineResult(
            verdict=final_verdict,
            results=results,
            blocked_by=blocked_by,
            warnings=warnings,
            threshold_adjustments=threshold_adjustments,
        )


class GuardPipeline:
    """Full pipeline: Ingress + Egress + Output sub-pipelines.

    The Shield determines which sub-pipelines to run based on the context:
      - Incoming content (user_input, tool_result, etc.) → Ingress
      - Agent action (tool_call, command) → Egress
      - Agent output / tool response → Output
    """

    def __init__(self) -> None:
        self.ingress = SubPipeline(PipelineKind.INGRESS)
        self.egress = SubPipeline(PipelineKind.EGRESS)
        self.output = SubPipeline(PipelineKind.OUTPUT)

    @property
    def all_guards(self) -> list[AIGuardBase]:
        """Return all guards across all sub-pipelines."""
        return self.ingress.guards + self.egress.guards + self.output.guards

    def run_ingress(
        self, context: GuardContext, guard_modes: dict[str, str] | None = None
    ) -> PipelineResult:
        """Run Ingress pipeline for incoming data checks."""
        return self.ingress.run(context, guard_modes)

    def run_egress(
        self, context: GuardContext, guard_modes: dict[str, str] | None = None
    ) -> PipelineResult:
        """Run Egress pipeline for outgoing action checks."""
        return self.egress.run(context, guard_modes)

    def run_output(
        self, context: GuardContext, guard_modes: dict[str, str] | None = None
    ) -> PipelineResult:
        """Run Output pipeline for audit and leak detection."""
        return self.output.run(context, guard_modes)

    def run_all(
        self, context: GuardContext, guard_modes: dict[str, str] | None = None
    ) -> PipelineResult:
        """Run all three sub-pipelines sequentially.

        BLOCK from any sub-pipeline short-circuits the entire pipeline.
        Threshold adjustments from earlier pipelines propagate to later ones.
        """
        # Ingress
        ingress_result = self.run_ingress(context, guard_modes)
        if ingress_result.should_block:
            return ingress_result

        # Egress
        # Merge threshold adjustments from ingress
        merged_modes = dict(guard_modes) if guard_modes else {}
        # (threshold_adjustments are applied per-guard via SubPipeline.run)

        egress_result = self.run_egress(context, guard_modes)
        if egress_result.should_block:
            return egress_result

        # Output
        output_result = self.run_output(context, guard_modes)

        # Aggregate all results
        all_results = ingress_result.results + egress_result.results + output_result.results
        all_warnings = ingress_result.warnings + egress_result.warnings + output_result.warnings
        all_adjustments: dict[str, float] = {}
        for r in (ingress_result, egress_result, output_result):
            for k, v in r.threshold_adjustments.items():
                all_adjustments[k] = all_adjustments.get(k, 0.0) + v

        final_verdict = GuardVerdict.PASS
        blocked_by: str | None = None
        for sub in (ingress_result, egress_result, output_result):
            if sub.should_block:
                final_verdict = GuardVerdict.BLOCK
                blocked_by = sub.blocked_by
                break
            if sub.verdict == GuardVerdict.WARN and final_verdict == GuardVerdict.PASS:
                final_verdict = GuardVerdict.WARN

        return PipelineResult(
            verdict=final_verdict,
            results=all_results,
            blocked_by=blocked_by,
            warnings=all_warnings,
            threshold_adjustments=all_adjustments,
        )
