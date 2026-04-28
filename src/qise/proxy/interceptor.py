"""ProxyInterceptor — routes parsed content through the Guard Pipeline.

Coordinates request and response interception:
  - Request interception: check user messages and tool results for injection (ingress)
  - Response interception: check tool calls for dangerous actions (egress)
  - Output interception: check response text for credential/PII leaks (output)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from qise.core.models import GuardContext, GuardVerdict, PipelineResult
from qise.proxy.parser import ParsedRequest, ParsedResponse


class ProxyDecision(BaseModel):
    """Decision returned by the proxy interceptor.

    Attributes:
        action: pass, warn, or block.
        modified_body: Modified request/response body (e.g., with injected context).
        warnings: List of warning messages from guards.
        block_reason: Human-readable reason for blocking (if action=block).
        guard_results: All guard results from the interception.
    """

    action: str = "pass"  # "pass" | "warn" | "block"
    modified_body: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    block_reason: str = ""
    guard_results: list[dict[str, Any]] = Field(default_factory=list)


class ProxyInterceptor:
    """Route parsed content through the Guard Pipeline.

    Usage:
        interceptor = ProxyInterceptor(shield)
        decision = interceptor.intercept_request(parsed_request, raw_body)
        decision = interceptor.intercept_response(parsed_response, raw_body)
    """

    def __init__(self, shield: Any, config: Any = None) -> None:
        """Initialize with a Shield instance.

        Args:
            shield: A Shield instance with a configured pipeline.
            config: Optional ProxyConfig for behavior tuning.
        """
        self._shield = shield
        self._config = config

    def intercept_request(
        self,
        parsed: ParsedRequest,
        raw_body: dict[str, Any],
    ) -> ProxyDecision:
        """Intercept a chat completion request.

        Checks:
          1. User messages for injection (ingress)
          2. Tool results for injection (ingress)
          3. Tool descriptions for poisoning (ingress)

        Returns:
            ProxyDecision with action pass/warn/block.
        """
        all_warnings: list[str] = []
        all_results: list[dict[str, Any]] = []
        should_block = False
        block_reason = ""

        guard_modes = {
            name: self._shield.config.guard_mode(name)
            for name in self._shield.config.guards.enabled
        }

        # Check each user message for injection
        for msg in parsed.messages:
            if msg.role == "user" and msg.content:
                trust_boundary = msg.trust_boundary or "user_input"
                ctx = GuardContext(
                    tool_name="content_check",
                    tool_args={"content": msg.content},
                    trust_boundary=trust_boundary,
                    integration_mode="proxy",
                )
                result = self._shield.pipeline.run_ingress(ctx, guard_modes)
                all_results.extend(self._summarize_results(result))
                all_warnings.extend(result.warnings)

                if result.should_block:
                    should_block = True
                    block_reason = f"Request blocked by guard: {result.blocked_by}"
                    break

        # Check tool descriptions for poisoning (if tools present)
        if not should_block:
            for tool_def in parsed.tools:
                if tool_def.description:
                    ctx = GuardContext(
                        tool_name=tool_def.name,
                        tool_args={},
                        tool_description=tool_def.description,
                        trust_boundary="tool_description",
                        integration_mode="proxy",
                    )
                    result = self._shield.pipeline.run_ingress(ctx, guard_modes)
                    all_results.extend(self._summarize_results(result))
                    all_warnings.extend(result.warnings)

                    if result.should_block:
                        should_block = True
                        block_reason = f"Tool description blocked: {result.blocked_by}"
                        break

        # Determine action
        if should_block:
            action = "block"
        elif all_warnings:
            action = "warn"
        else:
            action = "pass"

        return ProxyDecision(
            action=action,
            modified_body=raw_body,
            warnings=all_warnings,
            block_reason=block_reason,
            guard_results=all_results,
        )

    def intercept_response(
        self,
        parsed: ParsedResponse,
        raw_body: dict[str, Any],
    ) -> ProxyDecision:
        """Intercept a chat completion response.

        Checks:
          1. Tool calls for dangerous actions (egress)
          2. Reasoning content for manipulation traces (ingress/reasoning)
          3. Response text for credential/PII leaks (output)

        Returns:
            ProxyDecision with action pass/warn/block.
        """
        all_warnings: list[str] = []
        all_results: list[dict[str, Any]] = []
        should_block = False
        block_reason = ""

        guard_modes = {
            name: self._shield.config.guard_mode(name)
            for name in self._shield.config.guards.enabled
        }

        # Check tool calls for dangerous actions (egress)
        for tc in parsed.tool_calls:
            ctx = GuardContext(
                tool_name=tc.tool_name,
                tool_args=tc.tool_args,
                integration_mode="proxy",
                agent_reasoning=parsed.reasoning or None,
            )
            result = self._shield.pipeline.run_egress(ctx, guard_modes)
            all_results.extend(self._summarize_results(result))
            all_warnings.extend(result.warnings)

            if result.should_block:
                should_block = True
                block_reason = f"Tool call blocked by guard: {result.blocked_by}"
                break

        # Check response text for credential/PII leaks (output)
        if not should_block and parsed.content:
            ctx = GuardContext(
                tool_name="output",
                tool_args={"text": parsed.content},
                integration_mode="proxy",
            )
            result = self._shield.pipeline.run_output(ctx, guard_modes)
            all_results.extend(self._summarize_results(result))
            all_warnings.extend(result.warnings)

            if result.should_block:
                should_block = True
                block_reason = f"Output blocked by guard: {result.blocked_by}"

        # Determine action
        if should_block:
            action = "block"
        elif all_warnings:
            action = "warn"
        else:
            action = "pass"

        return ProxyDecision(
            action=action,
            modified_body=raw_body,
            warnings=all_warnings,
            block_reason=block_reason,
            guard_results=all_results,
        )

    def _summarize_results(self, result: PipelineResult) -> list[dict[str, Any]]:
        """Summarize pipeline results for the ProxyDecision."""
        summaries = []
        for gr in result.results:
            summary: dict[str, Any] = {
                "guard": gr.guard_name,
                "verdict": gr.verdict,
                "message": gr.message,
            }
            if gr.risk_attribution:
                summary["risk_source"] = gr.risk_attribution.risk_source
            summaries.append(summary)
        return summaries
