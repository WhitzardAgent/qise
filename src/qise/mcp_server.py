"""Qise MCP Server — exposes security checks as MCP tools.

Tools provided:
  - qise_check_tool_call: Check a tool call before execution
  - qise_check_content: Check incoming content for injection
  - qise_check_output: Check agent output for leaks
  - qise_get_security_context: Get security context for current operation

Usage:
    python -m qise.mcp_server

Configuration via QISE_CONFIG environment variable (defaults to ./shield.yaml).
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from qise.core.models import GuardContext
from qise.core.shield import Shield

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

app = Server("qise")


def _get_shield() -> Shield:
    """Get or create the Shield instance (lazy singleton)."""
    if not hasattr(_get_shield, "_instance"):
        config_path = os.getenv("QISE_CONFIG", "shield.yaml")
        _get_shield._instance = Shield.from_config(config_path)  # type: ignore[attr-defined]
    return _get_shield._instance  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="qise_check_tool_call",
            description="Check a tool call for security risks before execution. Returns PASS/WARN/BLOCK verdict with risk attribution.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool being called (e.g., 'bash', 'write_file', 'http_request')",
                    },
                    "tool_args": {
                        "type": "object",
                        "description": "Arguments passed to the tool",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session ID for cross-turn tracking",
                    },
                },
                "required": ["tool_name", "tool_args"],
            },
        ),
        Tool(
            name="qise_check_content",
            description="Check incoming content for prompt injection risks. Use for tool results, web content, or external data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The content to check for injection risks",
                    },
                    "trust_boundary": {
                        "type": "string",
                        "description": "Trust boundary of the content source (e.g., 'tool_result', 'web_content', 'mcp_response', 'user_input')",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session ID for cross-turn tracking",
                    },
                },
                "required": ["content", "trust_boundary"],
            },
        ),
        Tool(
            name="qise_check_output",
            description="Check agent output for credential leaks, PII exposure, or sensitive data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_text": {
                        "type": "string",
                        "description": "The agent output text to check for leaks",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Optional session ID for cross-turn tracking",
                    },
                },
                "required": ["output_text"],
            },
        ),
        Tool(
            name="qise_get_security_context",
            description="Get security context rules for the current operation. Inject these into your context to reduce security violations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Name of the tool about to be used",
                    },
                    "tool_args": {
                        "type": "object",
                        "description": "Optional tool arguments for context matching",
                    },
                },
                "required": ["tool_name"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    shield = _get_shield()

    if name == "qise_check_tool_call":
        return _handle_check_tool_call(shield, arguments)
    elif name == "qise_check_content":
        return _handle_check_content(shield, arguments)
    elif name == "qise_check_output":
        return _handle_check_output(shield, arguments)
    elif name == "qise_get_security_context":
        return _handle_get_security_context(shield, arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


def _handle_check_tool_call(shield: Shield, args: dict[str, Any]) -> list[TextContent]:
    tool_name = args["tool_name"]
    tool_args = args["tool_args"]
    session_id = args.get("session_id")

    context = GuardContext(
        tool_name=tool_name,
        tool_args=tool_args,
        session_id=session_id,
    )

    result = shield.pipeline.run_egress(context)

    # Record result in session tracker
    if session_id:
        for guard_result in result.results:
            shield.session_tracker.record_guard_result(session_id, guard_result)

    response = {
        "verdict": result.verdict,
        "blocked_by": result.blocked_by,
        "warnings": result.warnings,
    }
    if result.results:
        # Include the most relevant risk attribution
        for gr in result.results:
            if gr.risk_attribution:
                response["risk_attribution"] = gr.risk_attribution.model_dump()
                break

    import json
    return [TextContent(type="text", text=json.dumps(response, indent=2))]


def _handle_check_content(shield: Shield, args: dict[str, Any]) -> list[TextContent]:
    content = args["content"]
    trust_boundary = args["trust_boundary"]
    session_id = args.get("session_id")

    context = GuardContext(
        tool_name="content_check",
        tool_args={"content": content},
        trust_boundary=trust_boundary,
        session_id=session_id,
    )

    result = shield.pipeline.run_ingress(context)

    if session_id:
        for guard_result in result.results:
            shield.session_tracker.record_guard_result(session_id, guard_result)

    import json
    response = {"verdict": result.verdict, "warnings": result.warnings}
    return [TextContent(type="text", text=json.dumps(response, indent=2))]


def _handle_check_output(shield: Shield, args: dict[str, Any]) -> list[TextContent]:
    output_text = args["output_text"]
    session_id = args.get("session_id")

    context = GuardContext(
        tool_name="output_check",
        tool_args={"text": output_text},
        session_id=session_id,
    )

    result = shield.pipeline.run_output(context)

    if session_id:
        for guard_result in result.results:
            shield.session_tracker.record_guard_result(session_id, guard_result)

    import json
    response = {"verdict": result.verdict, "warnings": result.warnings}
    return [TextContent(type="text", text=json.dumps(response, indent=2))]


def _handle_get_security_context(shield: Shield, args: dict[str, Any]) -> list[TextContent]:
    tool_name = args["tool_name"]
    tool_args = args.get("tool_args")

    context_text = shield.get_security_context(tool_name, tool_args)
    return [TextContent(type="text", text=context_text)]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    """Run the MCP server via stdio transport."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
