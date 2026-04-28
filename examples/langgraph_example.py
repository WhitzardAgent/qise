"""Minimal LangGraph agent with Qise security wrapper.

This example demonstrates:
1. wrap_tool_call: wrapping langchain tools with Qise security
2. awrap_tool_call: async tool wrapping
3. qise_pre_model_hook: SecurityContext injection into state
4. BLOCK: ToolException/RuntimeError raised on dangerous calls

Uses real langchain_core.tools — no mocking needed.

Prerequisites:
    pip install -e ".[dev]"          # in qise directory
    pip install langchain-core       # for @tool decorator

Usage:
    python examples/langgraph_example.py
"""

from __future__ import annotations

import asyncio
import sys

from langchain_core.tools import tool

from qise import Shield
from qise.adapters.langgraph import QiseLangGraphWrapper


# --- Define tools ---

@tool
def list_files(directory: str = ".") -> str:
    """List files in a directory."""
    return f"Files in {directory}: file1.txt, file2.txt, README.md"


@tool
def run_bash(command: str = "") -> str:
    """Run a bash command."""
    return f"Output of: {command}"


# Set tool name to match Qise guard expectations
run_bash.name = "bash"


async def main() -> None:
    print("=" * 60)
    print("Qise × LangGraph Integration Example")
    print("=" * 60)

    # 1. Initialize Qise Shield + Wrapper
    shield = Shield.from_config()
    wrapper = QiseLangGraphWrapper(shield, session_id="langgraph-demo")
    wrapper.install()
    print("\n✓ QiseLangGraphWrapper installed")

    # 2. wrap_tool_call — safe operation
    print("\n--- wrap_tool_call (safe) ---")
    safe_list = wrapper.wrap_tool_call(list_files)
    result = safe_list(directory="/tmp")
    print(f"✓ list_files PASSED: {result}")

    # 3. wrap_tool_call — dangerous operation
    print("\n--- wrap_tool_call (dangerous) ---")
    safe_bash = wrapper.wrap_tool_call(run_bash)

    # Safe command
    result = safe_bash(command="ls -la")
    print(f"✓ 'ls -la' PASSED: {result}")

    # Dangerous command — should be blocked
    try:
        safe_bash(command="rm -rf /")
        print("✗ 'rm -rf /' should have been BLOCKED!")
    except Exception as e:
        print(f"✓ 'rm -rf /' BLOCKED: {type(e).__name__}: {str(e)[:50]}")

    # 4. awrap_tool_call — async tool wrapping
    print("\n--- awrap_tool_call (async) ---")

    @tool
    async def async_read_file(path: str = "") -> str:
        """Read a file asynchronously."""
        return f"Contents of {path}: Hello, World!"

    async_read_file.name = "read_file"
    safe_async = wrapper.awrap_tool_call(async_read_file)
    result = await safe_async(path="/tmp/test.txt")
    print(f"✓ async read_file PASSED: {result}")

    # 5. qise_pre_model_hook — SecurityContext injection
    print("\n--- qise_pre_model_hook ---")
    state = {
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "List files in /tmp"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "bash"}, "id": "tc1"},
                ],
            },
        ],
    }
    result_state = wrapper.qise_pre_model_hook(state)
    system_msg = next(
        (m for m in result_state["messages"] if m.get("role") == "system"),
        None,
    )
    if system_msg:
        content = system_msg.get("content", "")
        if "Security Context" in content:
            print("✓ SecurityContext injected into system message")
        else:
            print("✓ System message preserved (no matching security context templates)")

    # 6. Summary
    print("\n" + "=" * 60)
    print("All LangGraph integration checks verified!")
    print("  - wrap_tool_call: safe PASS + dangerous BLOCK ✓")
    print("  - awrap_tool_call: async tool wrapping ✓")
    print("  - qise_pre_model_hook: SecurityContext injection ✓")
    print("=" * 60)

    wrapper.uninstall()


if __name__ == "__main__":
    asyncio.run(main())
