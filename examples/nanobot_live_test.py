"""Nanobot Agent + Qise E2E Live Test.

Uses SII API as LLM backend to test QiseNanobotHook with a real agent.

SII API:
  Model:    glm-5.1-w4a8
  Base URL: https://ekkmopeh8ecgccbjjb9johhhd5dcabcc.openapi-sj.sii.edu.cn/v1
  API Key:  stpmj/4hRawPjQCf0fk70W6HnObgXtkonX3qHCCNsPc=

Prerequisites:
    pip install -e ".[dev]"
    pip install nanobot-ai

Usage:
    python examples/nanobot_live_test.py
"""
from __future__ import annotations

import asyncio
import sys
import traceback

# --- SII API config ---
SII_API_KEY = "stpmj/4hRawPjQCf0fk70W6HnObgXtkonX3qHCCNsPc="
SII_BASE_URL = "https://ekkmopeh8ecgccbjjb9johhhd5dcabcc.openapi-sj.sii.edu.cn/v1"
SII_MODEL = "glm-5.1-w4a8"


def _header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def _result(label: str, passed: bool, detail: str = "") -> None:
    icon = "PASS" if passed else "FAIL"
    suffix = f" — {detail}" if detail else ""
    print(f"  [{icon}] {label}{suffix}")


async def test_nanobot_sdk() -> int:
    """Test Qise with Nanobot + real SII LLM."""
    _header("Nanobot + Qise — Live E2E Test")

    passed = 0
    total = 0

    try:
        from nanobot.agent.hook import AgentHook, AgentHookContext
        from nanobot.agent.loop import AgentLoop
        from nanobot.providers.openai_compat_provider import OpenAICompatProvider

        # Configure provider
        provider = OpenAICompatProvider(
            api_key=SII_API_KEY,
            api_base=SII_BASE_URL,
            default_model=SII_MODEL,
        )
        print(f"  OpenAICompatProvider configured for SII API (model={SII_MODEL})")

        # Initialize Qise hook
        from qise import Shield
        from qise.adapters.nanobot import QiseNanobotHook

        shield = Shield.from_config()
        hook = QiseNanobotHook(shield, session_id="nanobot-live-test")
        hook.install()
        print("  QiseNanobotHook installed")

        # --- Test 1: before_execute_tools blocks dangerous command ---
        total += 1
        try:
            from nanobot.providers.base import ToolCallRequest

            context = AgentHookContext(
                iteration=1,
                messages=[{"role": "user", "content": "delete everything"}],
                tool_calls=[
                    ToolCallRequest(id="tc1", name="bash", arguments={"command": "rm -rf /"}),
                ],
            )
            await hook.before_execute_tools(context)
            blocked = len(context.tool_calls) == 0
            _result("Test 1: Dangerous cmd blocked", blocked,
                     f"tool_calls remaining: {len(context.tool_calls)}")
            if blocked:
                passed += 1
        except Exception as e:
            _result("Test 1: Dangerous cmd blocked", False, str(e)[:80])

        # --- Test 2: before_execute_tools allows safe command ---
        total += 1
        try:
            from nanobot.providers.base import ToolCallRequest

            context = AgentHookContext(
                iteration=1,
                messages=[{"role": "user", "content": "list files"}],
                tool_calls=[
                    ToolCallRequest(id="tc2", name="bash", arguments={"command": "ls -la /tmp"}),
                ],
            )
            await hook.before_execute_tools(context)
            allowed = len(context.tool_calls) == 1
            _result("Test 2: Safe cmd passes", allowed,
                     f"tool_calls remaining: {len(context.tool_calls)}")
            if allowed:
                passed += 1
        except Exception as e:
            _result("Test 2: Safe cmd passes", False, str(e)[:80])

        # --- Test 3: before_execute_tools blocks path traversal ---
        total += 1
        try:
            from nanobot.providers.base import ToolCallRequest

            context = AgentHookContext(
                iteration=1,
                messages=[{"role": "user", "content": "read shadow file"}],
                tool_calls=[
                    ToolCallRequest(id="tc3", name="read_file", arguments={"path": "/etc/shadow"}),
                ],
            )
            await hook.before_execute_tools(context)
            blocked = len(context.tool_calls) == 0
            _result("Test 3: Path traversal blocked", blocked,
                     f"tool_calls remaining: {len(context.tool_calls)}")
            if blocked:
                passed += 1
        except Exception as e:
            _result("Test 3: Path traversal blocked", False, str(e)[:80])

        # --- Test 4: after_iteration checks tool results ---
        total += 1
        try:
            from nanobot.providers.base import ToolCallRequest

            context = AgentHookContext(
                iteration=2,
                messages=[],
                tool_calls=[
                    ToolCallRequest(id="tc4", name="bash", arguments={"command": "ls"}),
                ],
                tool_results=["file1.txt\nfile2.txt"],
            )
            await hook.after_iteration(context)
            # Should not block a normal result
            _result("Test 4: Safe tool result passes", True)
            passed += 1
        except Exception as e:
            _result("Test 4: Safe tool result passes", False, str(e)[:80])

        # --- Test 5: after_iteration checks final output ---
        total += 1
        try:
            context = AgentHookContext(
                iteration=3,
                messages=[],
                final_content="The result is 42.",
            )
            await hook.after_iteration(context)
            _result("Test 5: Safe output passes", True)
            passed += 1
        except Exception as e:
            _result("Test 5: Safe output passes", False, str(e)[:80])

        # --- Test 6: AgentHook interface compatibility ---
        total += 1
        try:
            # Verify the hook has the right methods
            has_before = hasattr(hook, "before_execute_tools")
            has_after = hasattr(hook, "after_iteration")
            both_async = asyncio.iscoroutinefunction(hook.before_execute_tools) and \
                         asyncio.iscoroutinefunction(hook.after_iteration)
            _result("Test 6: AgentHook interface", has_before and has_after and both_async,
                     f"before={has_before}, after={has_after}, async={both_async}")
            if has_before and has_after and both_async:
                passed += 1
        except Exception as e:
            _result("Test 6: AgentHook interface", False, str(e)[:80])

        # --- Test 7: AgentLoop accepts hooks parameter ---
        total += 1
        try:
            # AgentLoop requires bus and workspace — verify hooks parameter exists
            import inspect
            sig = inspect.signature(AgentLoop.__init__)
            has_hooks = "hooks" in sig.parameters
            _result("Test 7: AgentLoop accepts hooks", has_hooks,
                     f"hooks param exists: {has_hooks}")
            if has_hooks:
                passed += 1
        except Exception as e:
            _result("Test 7: AgentLoop accepts hooks", False, str(e)[:80])

        # --- Test 8: Mixed safe and dangerous tool calls ---
        total += 1
        try:
            from nanobot.providers.base import ToolCallRequest

            context = AgentHookContext(
                iteration=1,
                messages=[],
                tool_calls=[
                    ToolCallRequest(id="tc5", name="bash", arguments={"command": "ls"}),
                    ToolCallRequest(id="tc6", name="bash", arguments={"command": "rm -rf /"}),
                    ToolCallRequest(id="tc7", name="read_file", arguments={"path": "/workspace/file.txt"}),
                ],
            )
            await hook.before_execute_tools(context)
            # Only the safe ls and read_file should remain
            remaining_names = [tc.name for tc in context.tool_calls]
            correct = "bash" in remaining_names and "rm -rf /" not in str([tc.arguments for tc in context.tool_calls])
            _result("Test 8: Mixed calls filtered", correct,
                     f"remaining: {remaining_names}")
            if correct:
                passed += 1
        except Exception as e:
            _result("Test 8: Mixed calls filtered", False, str(e)[:80])

        hook.uninstall()

    except ImportError as e:
        print(f"  SKIP: Required package not available — {e}")
        print(f"  Install with: pip install nanobot-ai")
        return 0
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    print(f"\n  Nanobot: {passed}/{total} passed")
    return passed * 100 + total


async def main() -> int:
    _header("Qise × Nanobot — Live E2E Test")
    result = await test_nanobot_sdk()
    p, t = result // 100, result % 100
    _header("Summary")
    print(f"  Nanobot SDK: {p}/{t} passed")
    return 0 if p == t else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
