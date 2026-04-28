"""Tests for SecurityContextProvider end-to-end via Shield."""

from qise.core.shield import Shield


class TestSecurityContextE2E:

    def test_bash_returns_shell_rules(self) -> None:
        shield = Shield.from_config()
        ctx = shield.get_security_context("bash", {"command": "ls"})
        assert ctx != ""
        assert "shell" in ctx.lower()

    def test_write_file_returns_file_rules(self) -> None:
        shield = Shield.from_config()
        ctx = shield.get_security_context("write_file", {"path": "/tmp/test"})
        assert ctx != ""
        assert "file" in ctx.lower()

    def test_unknown_tool_returns_empty(self) -> None:
        shield = Shield.from_config()
        ctx = shield.get_security_context("totally_unknown_tool_xyz", {})
        assert ctx == ""

    def test_no_crash_without_data_dir(self) -> None:
        from qise.core.config import ShieldConfig
        from qise.providers.security_context import SecurityContextProvider

        config = ShieldConfig(data={"security_contexts_dir": "/nonexistent/path"})
        provider = SecurityContextProvider("/nonexistent/path")
        result = provider.render_for_agent("bash", {"command": "ls"})
        assert result == ""
