"""Base adapter classes for Qise framework integration.

All adapters inherit from AgentAdapter and use IngressCheckMixin and/or
EgressCheckMixin to route content through the Guard Pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import time

from qise.core.models import GuardContext, PipelineResult, ToolCallRecord
from qise.core.shield import Shield


class IngressCheckMixin:
    """Mixin that provides ingress (World → Agent) guard checks.

    Use this in adapters that can intercept incoming content:
    user messages, tool results, MCP responses, etc.
    """

    shield: Shield

    def check_user_input(
        self,
        content: str,
        trust_boundary: str = "user_input",
        session_id: str | None = None,
    ) -> PipelineResult:
        """Check user input for injection attacks."""
        ctx = GuardContext(
            tool_name="content_check",
            tool_args={"content": content},
            trust_boundary=trust_boundary,
            session_id=session_id,
            integration_mode=self._integration_mode(),
        )
        guard_modes = {
            name: self.shield.config.guard_mode(name)
            for name in self.shield.config.guards.enabled
        }
        result = self.shield.pipeline.run_ingress(ctx, guard_modes)
        if session_id:
            for gr in result.results:
                self.shield.session_tracker.record_guard_result(session_id, gr)
        return result

    def check_tool_result(
        self,
        content: str,
        tool_name: str = "",
        session_id: str | None = None,
    ) -> PipelineResult:
        """Check tool result for injection attacks."""
        ctx = GuardContext(
            tool_name=tool_name or "tool_result",
            tool_args={"content": content},
            trust_boundary="tool_result",
            session_id=session_id,
            integration_mode=self._integration_mode(),
        )
        guard_modes = {
            name: self.shield.config.guard_mode(name)
            for name in self.shield.config.guards.enabled
        }
        result = self.shield.pipeline.run_ingress(ctx, guard_modes)
        if session_id:
            for gr in result.results:
                self.shield.session_tracker.record_guard_result(session_id, gr)
        return result

    def _integration_mode(self) -> str:
        return "sdk"


class EgressCheckMixin:
    """Mixin that provides egress (Agent → World) and output guard checks.

    Use this in adapters that can intercept outgoing actions:
    tool calls, commands, and output text.
    """

    shield: Shield

    def check_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        session_id: str | None = None,
        **kwargs: Any,
    ) -> PipelineResult:
        """Check a tool call for dangerous actions.

        Auto-fills active_security_rules from SecurityContextProvider.
        """
        security_rules = self._get_security_rules(tool_name, tool_args)
        ctx = GuardContext(
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=session_id,
            integration_mode=self._integration_mode(),
            active_security_rules=security_rules,
            **kwargs,
        )
        guard_modes = {
            name: self.shield.config.guard_mode(name)
            for name in self.shield.config.guards.enabled
        }
        result = self.shield.pipeline.run_egress(ctx, guard_modes)
        if session_id:
            for gr in result.results:
                self.shield.session_tracker.record_guard_result(session_id, gr)
            self.shield.session_tracker.record_tool_call(
                session_id,
                ToolCallRecord(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    verdict=result.verdict,
                    timestamp=time.time(),
                ),
            )
        return result

    def check_output(
        self,
        text: str,
        session_id: str | None = None,
    ) -> PipelineResult:
        """Check output text for credential/PII leaks.

        Args:
            text: The output text to check.
            session_id: Optional session ID for tracking.

        Returns:
            PipelineResult with should_block property.
        """
        ctx = GuardContext(
            tool_name="output",
            tool_args={"text": text},
            session_id=session_id,
            integration_mode=self._integration_mode(),
        )
        guard_modes = {
            name: self.shield.config.guard_mode(name)
            for name in self.shield.config.guards.enabled
        }
        result = self.shield.pipeline.run_output(ctx, guard_modes)
        if session_id:
            for gr in result.results:
                self.shield.session_tracker.record_guard_result(session_id, gr)
        return result

    def _integration_mode(self) -> str:
        return "sdk"

    def _get_security_rules(self, tool_name: str, tool_args: dict[str, Any] | None = None) -> list[str]:
        """Get security rules from SecurityContextProvider for the given tool."""
        ctx_text = self.shield.get_security_context(tool_name, tool_args)
        if not ctx_text:
            return []
        return [line for line in ctx_text.split("\n") if line.strip()]


class AgentAdapter(ABC):
    """Base class for framework-specific security adapters.

    All adapters must implement install() and uninstall() to manage
    their hooks/callbacks in the target framework.
    """

    def __init__(self, shield: Shield) -> None:
        self.shield = shield

    @abstractmethod
    def install(self) -> None:
        """Register hooks/callbacks into the framework."""

    @abstractmethod
    def uninstall(self) -> None:
        """Remove hooks/callbacks from the framework."""
