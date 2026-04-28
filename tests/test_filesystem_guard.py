"""Tests for FilesystemGuard."""

from qise.core.models import GuardContext, GuardVerdict
from qise.guards.filesystem import FilesystemGuard


class TestFilesystemGuardSystemDir:

    def test_blocks_etc_write(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="write_file", tool_args={"path": "/etc/passwd", "content": "hacked"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "System" in result.message

    def test_blocks_usr_write(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="write_file", tool_args={"path": "/usr/bin/malware", "content": "payload"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_blocks_var_write(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="write_file", tool_args={"path": "/var/log/evil.log", "content": "data"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_blocks_proc_access(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="read_file", tool_args={"path": "/proc/self/environ"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestFilesystemGuardPathTraversal:

    def test_blocks_dotdot_slash(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(
            tool_name="write_file",
            tool_args={"path": "../../../etc/passwd"},
            workspace_path="/home/user/project",
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "traversal" in result.message.lower()

    def test_blocks_dotdot_backslash(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(
            tool_name="write_file",
            tool_args={"path": "..\\..\\windows\\system32"},
            workspace_path="/home/user/project",
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestFilesystemGuardWorkspace:

    def test_blocks_outside_workspace(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(
            tool_name="write_file",
            tool_args={"path": "/home/other_user/secret.txt", "content": "data"},
            workspace_path="/home/user/project",
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "workspace" in result.message.lower()

    def test_allows_within_workspace(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(
            tool_name="write_file",
            tool_args={"path": "/home/user/project/src/main.py", "content": "code"},
            workspace_path="/home/user/project",
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_no_workspace_allows_any_path(self) -> None:
        guard = FilesystemGuard()
        # Without workspace_path, non-system paths should pass
        ctx = GuardContext(
            tool_name="write_file",
            tool_args={"path": "/home/user/data.txt", "content": "data"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestFilesystemGuardDeviceFiles:

    def test_blocks_dev_null(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="write_file", tool_args={"path": "/dev/null", "content": "data"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "Device" in result.message

    def test_blocks_dev_urandom(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="read_file", tool_args={"path": "/dev/urandom"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestFilesystemGuardDangerousOps:

    def test_blocks_delete_on_system_path(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(
            tool_name="file_op",
            tool_args={"path": "/etc/hosts", "operation": "delete"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_allows_delete_in_workspace(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(
            tool_name="file_op",
            tool_args={"path": "/home/user/project/tmp.txt", "operation": "delete"},
            workspace_path="/home/user/project",
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestFilesystemGuardClean:

    def test_clean_file_write_passes(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(
            tool_name="write_file",
            tool_args={"path": "/home/user/project/output.txt", "content": "Hello"},
            workspace_path="/home/user/project",
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_filepath_key_recognized(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="write", tool_args={"filepath": "/etc/shadow", "data": "x"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_no_path_keys_passes(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "echo hello"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestFilesystemGuardModelDegradation:

    def test_full_check_blocks_system_dir(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(tool_name="write_file", tool_args={"path": "/etc/passwd", "content": "x"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_full_check_clean_passes(self) -> None:
        guard = FilesystemGuard()
        ctx = GuardContext(
            tool_name="write_file",
            tool_args={"path": "/home/user/project/f.txt", "content": "ok"},
            workspace_path="/home/user/project",
        )
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.PASS
