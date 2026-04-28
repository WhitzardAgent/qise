"""Tests for ToolPolicyGuard."""

from qise.core.models import GuardContext, GuardVerdict
from qise.guards.tool_policy import ToolPolicyGuard, ToolPolicyProfile


class TestToolPolicyGuardDeny:

    def test_blocks_denylisted_tool(self) -> None:
        profiles = {
            "default": ToolPolicyProfile(deny=["sudo", "docker*", "kubectl"]),
        }
        guard = ToolPolicyGuard(profiles=profiles, active_profile="default")

        ctx = GuardContext(tool_name="sudo", tool_args={})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "denied" in result.message.lower()

    def test_blocks_glob_match(self) -> None:
        profiles = {
            "default": ToolPolicyProfile(deny=["docker*"]),
        }
        guard = ToolPolicyGuard(profiles=profiles, active_profile="default")

        ctx = GuardContext(tool_name="docker_run", tool_args={})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_allows_non_denylisted(self) -> None:
        profiles = {
            "default": ToolPolicyProfile(deny=["sudo", "docker*"]),
        }
        guard = ToolPolicyGuard(profiles=profiles, active_profile="default")

        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestToolPolicyGuardApproval:

    def test_requires_approval(self) -> None:
        profiles = {
            "default": ToolPolicyProfile(require_approval=["database_write", "file_write"]),
        }
        guard = ToolPolicyGuard(profiles=profiles, active_profile="default")

        ctx = GuardContext(tool_name="database_write", tool_args={})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.APPROVE
        assert "approval" in result.message.lower()

    def test_non_approval_tool_passes(self) -> None:
        profiles = {
            "default": ToolPolicyProfile(require_approval=["database_write"]),
        }
        guard = ToolPolicyGuard(profiles=profiles, active_profile="default")

        ctx = GuardContext(tool_name="database_read", tool_args={})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestToolPolicyGuardOwnerOnly:

    def test_blocks_non_owner(self) -> None:
        profiles = {
            "default": ToolPolicyProfile(owner_only={"admin_tool": ["admin", "root"]}),
        }
        guard = ToolPolicyGuard(profiles=profiles, active_profile="default")

        ctx = GuardContext(tool_name="admin_tool", tool_args={}, user_id="guest")
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "owner" in result.message.lower()

    def test_allows_owner(self) -> None:
        profiles = {
            "default": ToolPolicyProfile(owner_only={"admin_tool": ["admin", "root"]}),
        }
        guard = ToolPolicyGuard(profiles=profiles, active_profile="default")

        ctx = GuardContext(tool_name="admin_tool", tool_args={}, user_id="admin")
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestToolPolicyGuardDefault:

    def test_empty_profile_passes(self) -> None:
        guard = ToolPolicyGuard()
        ctx = GuardContext(tool_name="any_tool", tool_args={})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_unknown_profile_passes(self) -> None:
        profiles = {"strict": ToolPolicyProfile(deny=["*"])}
        guard = ToolPolicyGuard(profiles=profiles, active_profile="nonexistent")
        ctx = GuardContext(tool_name="sudo", tool_args={})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestToolPolicyGuardModelDegradation:

    def test_full_check_blocks_denylisted(self) -> None:
        profiles = {"default": ToolPolicyProfile(deny=["sudo"])}
        guard = ToolPolicyGuard(profiles=profiles, active_profile="default")
        ctx = GuardContext(tool_name="sudo", tool_args={})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
