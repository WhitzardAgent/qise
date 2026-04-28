"""LangGraph adapter — routes tool calls through Qise Shield via wrapper functions.

Uses LangGraph's ToolNode and model hooks for non-invasive integration:
- wrap_tool_call / awrap_tool_call: Intercept and check tool calls before execution
- qise_pre_model_hook: Inject SecurityContext into messages before model call

BLOCK strategy:
- wrap_tool_call: Raise ToolException with block reason
- awrap_tool_call: Raise ToolException with block reason

Usage:
    from qise import Shield
    from qise.adapters.langgraph import QiseLangGraphWrapper

    shield = Shield.from_config()
    wrapper = QiseLangGraphWrapper(shield)

    # Wrap tools for LangGraph ToolNode
    safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]

    # Or use async version
    safe_tools = [wrapper.awrap_tool_call(tool) for tool in my_tools]

    # Add pre-model hook for SecurityContext injection
    graph.add_node("pre_model", wrapper.qise_pre_model_hook)
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any

from qise.adapters.base import AgentAdapter, EgressCheckMixin, IngressCheckMixin
from qise.core.shield import Shield

logger = logging.getLogger("qise.adapters.langgraph")


class QiseLangGraphWrapper(AgentAdapter, IngressCheckMixin, EgressCheckMixin):
    """LangGraph tool wrapper that routes tool calls through Qise Shield.

    Integration points:
      - wrap_tool_call: Synchronous wrapper — raises ToolException on block
      - awrap_tool_call: Async wrapper — raises ToolException on block
      - qise_pre_model_hook: Injects SecurityContext into state messages
    """

    def __init__(self, shield: Shield, session_id: str | None = None) -> None:
        super().__init__(shield)
        self.session_id = session_id
        self._installed = False

    def install(self) -> None:
        """Mark wrapper as installed."""
        self._installed = True
        logger.info("QiseLangGraphWrapper installed")

    def uninstall(self) -> None:
        """Mark wrapper as uninstalled."""
        self._installed = False
        logger.info("QiseLangGraphWrapper uninstalled")

    # ------------------------------------------------------------------
    # Tool call wrappers
    # ------------------------------------------------------------------

    def wrap_tool_call(self, tool: Callable) -> Callable:
        """Wrap a synchronous tool function with Qise security checks.

        Before executing the tool, runs egress checks. If blocked,
        raises ToolException instead of executing.

        Args:
            tool: The original tool function to wrap.

        Returns:
            Wrapped function that checks security before execution.
        """

        @functools.wraps(tool)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            tool_name = getattr(tool, "name", None) or tool.__name__
            tool_args = kwargs if kwargs else {"args": str(args)}

            result = self.check_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
            )

            if result.should_block:
                reason = f"Qise blocked: {result.blocked_by}"
                logger.warning("LangGraph: blocked %s — %s", tool_name, reason)
                # Try to import ToolException from langgraph, fall back to RuntimeError
                try:
                    from langgraph.tools import ToolException
                    raise ToolException(reason)
                except ImportError:
                    raise RuntimeError(reason)

            # Handle langchain BaseTool objects (use .invoke()) vs plain functions
            if hasattr(tool, "invoke") and callable(tool.invoke):
                return tool.invoke(tool_args)
            return tool(*args, **kwargs)

        return wrapped

    def awrap_tool_call(self, tool: Callable) -> Callable:
        """Wrap an async tool function with Qise security checks.

        Before executing the tool, runs egress checks. If blocked,
        raises ToolException instead of executing.

        Args:
            tool: The original async tool function to wrap.

        Returns:
            Wrapped async function that checks security before execution.
        """

        @functools.wraps(tool)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            tool_name = getattr(tool, "name", None) or tool.__name__
            tool_args = kwargs if kwargs else {"args": str(args)}

            result = self.check_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
            )

            if result.should_block:
                reason = f"Qise blocked: {result.blocked_by}"
                logger.warning("LangGraph: blocked %s — %s", tool_name, reason)
                try:
                    from langgraph.tools import ToolException
                    raise ToolException(reason)
                except ImportError:
                    raise RuntimeError(reason)

            # Handle langchain BaseTool objects (use .ainvoke()) vs plain functions
            if hasattr(tool, "ainvoke") and callable(tool.ainvoke):
                return await tool.ainvoke(tool_args)
            return await tool(*args, **kwargs)

        return wrapped

    # ------------------------------------------------------------------
    # Model hooks
    # ------------------------------------------------------------------

    def qise_pre_model_hook(self, state: dict[str, Any]) -> dict[str, Any]:
        """LangGraph pre-model hook: inject SecurityContext into messages.

        Scans messages for tool names and injects relevant security rules
        into the system message.

        Args:
            state: LangGraph state dict with "messages" key.

        Returns:
            Updated state dict with security context injected.
        """
        messages = state.get("messages", [])
        if not messages:
            return state

        # Collect tool names from messages
        tool_names = set()
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content", "")
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            tool_names.add(block.get("name", ""))
                for tc in msg.get("tool_calls", []):
                    if isinstance(tc, dict):
                        name = tc.get("function", {}).get("name", "")
                        if name:
                            tool_names.add(name)
            else:
                # LangChain message objects
                additional_kwargs = getattr(msg, "additional_kwargs", {})
                for tc in additional_kwargs.get("tool_calls", []):
                    if isinstance(tc, dict):
                        name = tc.get("function", {}).get("name", "")
                        if name:
                            tool_names.add(name)

        if not tool_names:
            return state

        # Build security context text
        context_parts: list[str] = []
        for tn in tool_names:
            ctx_text = self.shield.get_security_context(tn, None)
            if ctx_text:
                context_parts.append(ctx_text)

        if not context_parts:
            return state

        security_text = "\n".join(context_parts)

        # Inject into system message or prepend as new system message
        new_messages = list(messages)
        injected = False

        for i, msg in enumerate(new_messages):
            role = msg.get("role", "") if isinstance(msg, dict) else getattr(msg, "type", "")
            if role == "system":
                if isinstance(msg, dict):
                    msg["content"] = msg.get("content", "") + "\n\n" + security_text
                else:
                    existing = getattr(msg, "content", "")
                    msg.content = existing + "\n\n" + security_text
                injected = True
                break

        if not injected:
            # Prepend a new system message
            try:
                from langchain_core.messages import SystemMessage
                new_messages.insert(0, SystemMessage(content=security_text))
            except ImportError:
                new_messages.insert(0, {"role": "system", "content": security_text})

        return {**state, "messages": new_messages}
