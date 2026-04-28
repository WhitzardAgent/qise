"""OpenAI Agents SDK adapter — routes actions through Qise Shield via Guardrails.

Uses OpenAI Agents SDK's guardrails mechanism for non-invasive integration:
- tool_input_guardrail: Check tool call arguments before execution
- tool_output_guardrail: Check tool results for injection after execution
- input_guardrail: Check user input for injection attacks
- output_guardrail: Check agent output for credential/PII leaks

BLOCK strategy: Return GuardrailFunctionOutput with tripwire_triggered=True.

Usage:
    from qise import Shield
    from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails

    shield = Shield.from_config()
    guardrails = QiseOpenAIAgentsGuardrails(shield)

    # Register with OpenAI Agent
    agent = Agent(
        name="my-agent",
        guardrails=[
            guardrails.input_guardrail,
            guardrails.output_guardrail,
        ],
    )

    # Wrap tools with tool guardrails
    for tool in tools:
        tool.on_invoke = guardrails.wrap_tool(tool)
"""

from __future__ import annotations

import logging
from typing import Any

from qise.adapters.base import AgentAdapter, EgressCheckMixin, IngressCheckMixin
from qise.core.shield import Shield

logger = logging.getLogger("qise.adapters.openai_agents")


class QiseOpenAIAgentsGuardrails(AgentAdapter, IngressCheckMixin, EgressCheckMixin):
    """OpenAI Agents SDK guardrails that route actions through Qise Shield.

    Provides four guardrail functions compatible with the OpenAI Agents SDK:
      - input_guardrail: Check user input for injection
      - output_guardrail: Check agent output for leaks
      - tool_input_guardrail: Check tool call arguments
      - tool_output_guardrail: Check tool results for injection

    BLOCK strategy: Return GuardrailFunctionOutput with tripwire_triggered=True.
    """

    def __init__(self, shield: Shield, session_id: str | None = None) -> None:
        super().__init__(shield)
        self.session_id = session_id
        self._installed = False

    def install(self) -> None:
        """Mark guardrails as installed."""
        self._installed = True
        logger.info("QiseOpenAIAgentsGuardrails installed")

    def uninstall(self) -> None:
        """Mark guardrails as uninstalled."""
        self._installed = False
        logger.info("QiseOpenAIAgentsGuardrails uninstalled")

    # ------------------------------------------------------------------
    # Guardrail functions
    # ------------------------------------------------------------------

    async def input_guardrail(self, context: Any, input_data: Any) -> Any:
        """Check user input for injection attacks.

        Args:
            context: Agent context (RunContextWrapper).
            input_data: User input (str or message list).

        Returns:
            GuardrailFunctionOutput with tripwire_triggered if blocked.
        """
        # Extract text from input
        text = ""
        if isinstance(input_data, str):
            text = input_data
        elif isinstance(input_data, list):
            # Message list format
            for msg in input_data:
                if isinstance(msg, dict) and msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        text += content + "\n"
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                text += block.get("text", "") + "\n"
        else:
            text = str(getattr(input_data, "content", ""))

        if not text.strip():
            return self._guardrail_output(False, "No input to check")

        result = self.check_user_input(
            content=text.strip(),
            trust_boundary="user_input",
            session_id=self.session_id,
        )

        if result.should_block:
            logger.warning("OpenAI Agents: input blocked — %s", result.blocked_by)
            return self._guardrail_output(
                True,
                f"Blocked: {result.blocked_by}",
            )

        return self._guardrail_output(False, "Input passed security check")

    async def output_guardrail(self, context: Any, output_data: Any) -> Any:
        """Check agent output for credential/PII leaks.

        Args:
            context: Agent context (RunContextWrapper).
            output_data: Agent output (str or response object).

        Returns:
            GuardrailFunctionOutput with tripwire_triggered if blocked.
        """
        # Extract text from output
        text = ""
        if isinstance(output_data, str):
            text = output_data
        else:
            text = str(getattr(output_data, "content", "") or "")

        if not text.strip():
            return self._guardrail_output(False, "No output to check")

        result = self.check_output(
            text=text.strip(),
            session_id=self.session_id,
        )

        if result.should_block:
            logger.warning("OpenAI Agents: output blocked — %s", result.blocked_by)
            return self._guardrail_output(
                True,
                f"Blocked: {result.blocked_by}",
            )

        return self._guardrail_output(False, "Output passed security check")

    async def tool_input_guardrail(self, context: Any, tool_name: str, tool_args: dict[str, Any]) -> Any:
        """Check tool call arguments before execution.

        Args:
            context: Agent context (RunContextWrapper).
            tool_name: Name of the tool being called.
            tool_args: Arguments passed to the tool.

        Returns:
            GuardrailFunctionOutput with tripwire_triggered if blocked.
        """
        result = self.check_tool_call(
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=self.session_id,
        )

        if result.should_block:
            logger.warning(
                "OpenAI Agents: tool %s blocked — %s",
                tool_name,
                result.blocked_by,
            )
            return self._guardrail_output(
                True,
                f"Blocked: {result.blocked_by}",
            )

        return self._guardrail_output(False, f"Tool {tool_name} passed security check")

    async def tool_output_guardrail(self, context: Any, tool_name: str, tool_result: str) -> Any:
        """Check tool result for injection after execution.

        Args:
            context: Agent context (RunContextWrapper).
            tool_name: Name of the tool that produced the result.
            tool_result: The tool execution result text.

        Returns:
            GuardrailFunctionOutput with tripwire_triggered if blocked.
        """
        result = self.check_tool_result(
            content=str(tool_result),
            tool_name=tool_name,
            session_id=self.session_id,
        )

        if result.should_block:
            logger.warning(
                "OpenAI Agents: tool result from %s blocked — %s",
                tool_name,
                result.blocked_by,
            )
            return self._guardrail_output(
                True,
                f"Blocked: {result.blocked_by}",
            )

        return self._guardrail_output(False, f"Tool result from {tool_name} passed security check")

    # ------------------------------------------------------------------
    # Tool wrapper
    # ------------------------------------------------------------------

    def wrap_tool(self, tool: Any) -> Any:
        """Wrap a tool with input/output guardrails.

        Args:
            tool: The original tool (function or BaseTool instance).

        Returns:
            The same tool with guardrail checks applied.
        """
        original_invoke = getattr(tool, "on_invoke", None)

        if original_invoke is None:
            # If the tool is a plain function, return a wrapped function
            if callable(tool):
                import functools

                @functools.wraps(tool)
                async def wrapped_invoke(*args: Any, **kwargs: Any) -> Any:
                    tool_name = getattr(tool, "name", None) or tool.__name__
                    result = self.check_tool_call(
                        tool_name=tool_name,
                        tool_args=kwargs if kwargs else {"args": str(args)},
                        session_id=self.session_id,
                    )
                    if result.should_block:
                        raise RuntimeError(f"Qise blocked: {result.blocked_by}")

                    output = tool(*args, **kwargs)
                    if hasattr(output, "__await__"):
                        output = await output

                    # Check tool result
                    self.check_tool_result(
                        content=str(output),
                        tool_name=tool_name,
                        session_id=self.session_id,
                    )
                    return output

                return wrapped_invoke
            return tool

        # Wrap on_invoke method
        async def guarded_invoke(ctx: Any, *args: Any, **kwargs: Any) -> Any:
            tool_name = getattr(tool, "name", "") or "unknown"
            result = self.check_tool_call(
                tool_name=tool_name,
                tool_args=kwargs if kwargs else {"args": str(args)},
                session_id=self.session_id,
            )
            if result.should_block:
                raise RuntimeError(f"Qise blocked: {result.blocked_by}")

            output = await original_invoke(ctx, *args, **kwargs)

            # Check tool result
            self.check_tool_result(
                content=str(output),
                tool_name=tool_name,
                session_id=self.session_id,
            )
            return output

        tool.on_invoke = guarded_invoke
        return tool

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _guardrail_output(self, tripwire_triggered: bool, reason: str) -> dict[str, Any]:
        """Build a guardrail output dict compatible with OpenAI Agents SDK.

        Returns a dict that matches the GuardrailFunctionOutput interface.
        If the SDK is available, returns the actual object; otherwise a dict.
        """
        try:
            from agents import GuardrailFunctionOutput
            return GuardrailFunctionOutput(
                output_info={"reason": reason, "source": "qise"},
                tripwire_triggered=tripwire_triggered,
            )
        except ImportError:
            return {
                "output_info": {"reason": reason, "source": "qise"},
                "tripwire_triggered": tripwire_triggered,
            }
