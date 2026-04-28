"""Tests for CLI commands — subprocess-based integration tests."""

import json
import subprocess
import sys


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "qise"] + args,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestCLIVersion:

    def test_version_output(self) -> None:
        result = _run(["version"])
        assert result.returncode == 0
        assert "0.1.0" in result.stdout


class TestCLICheck:

    def test_check_blocks_rm_rf(self) -> None:
        result = _run(["check", "bash", '{"command": "rm -rf /"}'])
        assert result.returncode != 0
        assert "block" in result.stdout.lower()

    def test_check_passes_ls(self) -> None:
        result = _run(["check", "bash", '{"command": "ls -la"}', "--pipeline", "egress"])
        assert result.returncode == 0
        assert "pass" in result.stdout.lower() or "warn" in result.stdout.lower()


class TestCLIGuards:

    def test_guards_lists_all(self) -> None:
        result = _run(["guards"])
        assert result.returncode == 0
        for name in ("prompt", "command", "credential", "output"):
            assert name in result.stdout


class TestCLIContext:

    def test_context_bash_returns_rules(self) -> None:
        result = _run(["context", "bash"])
        assert result.returncode == 0
        assert "shell" in result.stdout.lower() or "security context" in result.stdout.lower()


class TestCLINoArgs:

    def test_no_args_shows_usage(self) -> None:
        result = _run([])
        assert result.returncode != 0
        assert "usage" in result.stderr.lower() or "qise" in result.stderr.lower()
