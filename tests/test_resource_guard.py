"""Tests for ResourceGuard."""

from qise.core.models import GuardContext, GuardResult, GuardVerdict, ToolCallRecord
from qise.guards.resource import ResourceGuard


class TestResourceGuardIterationBudget:

    def test_blocks_over_max_iterations(self) -> None:
        guard = ResourceGuard(max_iterations=10)
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            iteration_count=11,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "iteration" in result.message.lower()

    def test_allows_under_max_iterations(self) -> None:
        guard = ResourceGuard(max_iterations=10)
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            iteration_count=5,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestResourceGuardAPICallBudget:

    def test_blocks_over_max_api_calls(self) -> None:
        guard = ResourceGuard(max_api_calls=10)
        history = [ToolCallRecord(tool_name="bash", tool_args={}, verdict="pass") for _ in range(11)]
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            tool_call_history=history,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "api call" in result.message.lower()

    def test_allows_under_max_api_calls(self) -> None:
        guard = ResourceGuard(max_api_calls=10)
        # Use varied tool names to avoid loop detection
        history = [
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="read_file", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="write_file", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="search", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="pass"),
        ]
        ctx = GuardContext(
            tool_name="git_status",
            tool_args={},
            tool_call_history=history,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestResourceGuardLoopDetection:

    def test_warns_on_repetitive_calls(self) -> None:
        guard = ResourceGuard()
        # 4 of last 5 are the same tool
        history = [
            ToolCallRecord(tool_name="read_file", tool_args={"path": "/tmp/a"}, verdict="pass"),
            ToolCallRecord(tool_name="read_file", tool_args={"path": "/tmp/b"}, verdict="pass"),
            ToolCallRecord(tool_name="read_file", tool_args={"path": "/tmp/c"}, verdict="pass"),
            ToolCallRecord(tool_name="read_file", tool_args={"path": "/tmp/d"}, verdict="pass"),
            ToolCallRecord(tool_name="bash", tool_args={"command": "ls"}, verdict="pass"),
        ]
        ctx = GuardContext(
            tool_name="read_file",
            tool_args={"path": "/tmp/e"},
            tool_call_history=history,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.WARN
        assert "loop" in result.message.lower()

    def test_no_warn_on_varied_calls(self) -> None:
        guard = ResourceGuard()
        history = [
            ToolCallRecord(tool_name="read_file", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="write_file", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="search", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="pass"),
        ]
        ctx = GuardContext(
            tool_name="read_file",
            tool_args={"path": "/tmp/e"},
            tool_call_history=history,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestResourceGuardCircuitBreaker:

    def test_warns_on_consecutive_failures(self) -> None:
        guard = ResourceGuard(circuit_breaker_threshold=3)
        history = [
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="block"),
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="warn"),
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="block"),
        ]
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            tool_call_history=history,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.WARN
        assert "circuit" in result.message.lower() or "failure" in result.message.lower()

    def test_no_warn_when_passes_mixed_in(self) -> None:
        guard = ResourceGuard(circuit_breaker_threshold=3)
        history = [
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="block"),
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="pass"),
            ToolCallRecord(tool_name="bash", tool_args={}, verdict="block"),
        ]
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            tool_call_history=history,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestResourceGuardClean:

    def test_clean_low_iteration_passes(self) -> None:
        guard = ResourceGuard()
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            iteration_count=1,
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestResourceGuardModelDegradation:

    def test_full_check_blocks_over_budget(self) -> None:
        guard = ResourceGuard(max_iterations=10)
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            iteration_count=11,
        )
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_full_check_clean_passes(self) -> None:
        guard = ResourceGuard()
        ctx = GuardContext(
            tool_name="bash",
            tool_args={"command": "ls"},
            iteration_count=1,
        )
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.PASS
