"""Hermes adapter — routes tool calls through Qise Shield via Plugin hooks.

Uses Hermes's register_hook() mechanism for non-invasive integration:
- pre_tool_call: block dangerous tool calls by returning {"action": "skip"}
- transform_tool_result: check tool results for injection, replace if blocked
- post_tool_call: log results to session tracker
- post_llm_call: check LLM output for credential/PII leaks

BLOCK strategy: Return {"action": "skip", "reason": "..."} from pre_tool_call
to prevent tool execution. This is more direct than Nanobot's list mutation.

Usage:
    # In plugin.yaml:
    #   name: qise-security
    #   provides_hooks: [pre_tool_call, post_tool_call, transform_tool_result, post_llm_call]

    # In __init__.py:
    from qise import Shield
    from qise.adapters.hermes import QiseHermesPlugin

    def register(ctx):
        shield = Shield.from_config()
        plugin = QiseHermesPlugin(shield)
        plugin.register(ctx)
"""

from __future__ import annotations

import logging
from typing import Any

from qise.adapters.base import AgentAdapter, EgressCheckMixin, IngressCheckMixin
from qise.core.shield import Shield

logger = logging.getLogger("qise.adapters.hermes")


class QiseHermesPlugin(AgentAdapter, IngressCheckMixin, EgressCheckMixin):
    """Hermes plugin that registers Qise security hooks.

    Hooks registered:
      - pre_tool_call: Block dangerous tool calls via {"action": "skip"}
      - transform_tool_result: Sanitize tool results with injection content
      - post_tool_call: Record results in session tracker
      - post_llm_call: Check LLM output for leaks
    """

    def __init__(self, shield: Shield, session_id: str | None = None) -> None:
        super().__init__(shield)
        self.session_id = session_id
        self._plugin_context: Any = None

    def install(self) -> None:
        """Register hooks via the stored plugin context."""
        if self._plugin_context is not None:
            self.register(self._plugin_context)

    def uninstall(self) -> None:
        """Clear plugin context. Hermes handles hook deregistration."""
        self._plugin_context = None
        logger.info("QiseHermesPlugin uninstalled")

    def register(self, plugin_context: Any) -> None:
        """Register all Qise hooks into Hermes.

        Args:
            plugin_context: Hermes PluginContext with register_hook() method.
        """
        self._plugin_context = plugin_context
        register = getattr(plugin_context, "register_hook", None)
        if register is None:
            logger.error("Hermes plugin_context has no register_hook method")
            return

        register("pre_tool_call", self._on_pre_tool_call)
        register("post_tool_call", self._on_post_tool_call)
        register("transform_tool_result", self._on_transform_tool_result)
        register("post_llm_call", self._on_post_llm_call)
        logger.info("QiseHermesPlugin registered 4 hooks")

    def _on_pre_tool_call(
        self,
        tool_name: str,
        params: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, str] | None:
        """Block dangerous tool calls by returning skip action.

        Returns:
            {"action": "skip", "reason": "..."} to block, or None to allow.
        """
        result = self.check_tool_call(
            tool_name=tool_name,
            tool_args=params,
            session_id=self.session_id,
        )

        if result.should_block:
            reason = f"Qise blocked: {result.blocked_by}"
            logger.warning("Hermes: blocked %s — %s", tool_name, reason)
            return {"action": "skip", "reason": reason}

        return None

    def _on_transform_tool_result(
        self,
        tool_name: str,
        result_text: str,
        **kwargs: Any,
    ) -> str:
        """Check tool result for injection — replace if blocked.

        Returns:
            Original text if safe, or replacement message if blocked.
        """
        result = self.check_tool_result(
            content=result_text,
            tool_name=tool_name,
            session_id=self.session_id,
        )

        if result.should_block:
            logger.warning(
                "Hermes: replaced tool result from %s — %s",
                tool_name,
                result.blocked_by,
            )
            return "[Qise: potentially malicious content removed]"

        return result_text

    def _on_post_tool_call(
        self,
        tool_name: str,
        params: dict[str, Any],
        result: Any,
        **kwargs: Any,
    ) -> None:
        """Record tool call result in session tracker."""
        if self.session_id:
            from qise.core.models import ToolCallRecord
            import time

            self.shield.session_tracker.record_tool_call(
                self.session_id,
                ToolCallRecord(
                    tool_name=tool_name,
                    tool_args=params,
                    verdict="pass",
                    timestamp=time.time(),
                ),
            )

    def _on_post_llm_call(self, response: Any, **kwargs: Any) -> None:
        """Check LLM output for credential/PII leaks.

        Extracts text content from the response and runs output checks.
        """
        # Extract text from response — handle various response formats
        text = ""
        if isinstance(response, str):
            text = response
        elif isinstance(response, dict):
            choices = response.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                text = message.get("content", "")
        else:
            text = str(getattr(response, "content", ""))

        if not text:
            return

        result = self.check_output(
            text=text,
            session_id=self.session_id,
        )

        if result.should_block:
            logger.warning("Hermes: LLM output blocked — %s", result.blocked_by)
