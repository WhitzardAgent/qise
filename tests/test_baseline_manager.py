"""Tests for BaselineManager."""

import tempfile
from pathlib import Path

import pytest

from qise.data.baseline_manager import BaselineManager


@pytest.fixture
def mgr() -> BaselineManager:
    with tempfile.TemporaryDirectory() as tmpdir:
        yield BaselineManager(Path(tmpdir))


class TestBaselineManager:

    def test_compute_hash_deterministic(self) -> None:
        h1 = BaselineManager.compute_hash("hello")
        h2 = BaselineManager.compute_hash("hello")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_compute_hash_different_content(self) -> None:
        h1 = BaselineManager.compute_hash("hello")
        h2 = BaselineManager.compute_hash("world")
        assert h1 != h2

    def test_record_and_check_tool_baseline(self, mgr: BaselineManager) -> None:
        mgr.record_tool_baseline("bash", "Execute a bash command")
        result = mgr.check_tool_baseline("bash", "Execute a bash command")
        assert result.matches is True
        assert result.changed is False

    def test_detect_tool_baseline_change(self, mgr: BaselineManager) -> None:
        mgr.record_tool_baseline("bash", "Execute a bash command")
        result = mgr.check_tool_baseline("bash", "Execute a bash command WITH MALICIOUS ADDITION")
        assert result.matches is False
        assert result.changed is True

    def test_no_baseline_recorded(self, mgr: BaselineManager) -> None:
        result = mgr.check_tool_baseline("unknown_tool", "some description")
        assert result.matches is False
        assert result.changed is False
        assert result.previous_hash is None

    def test_kb_baseline(self, mgr: BaselineManager) -> None:
        mgr.record_kb_baseline("doc_001", "KB content here", source="internal")
        result = mgr.check_kb_baseline("doc_001", "KB content here")
        assert result.matches is True

    def test_memory_baseline(self, mgr: BaselineManager) -> None:
        mgr.record_memory_baseline("mem_001", "User prefers concise responses")
        result = mgr.check_memory_baseline("mem_001", "User prefers concise responses")
        assert result.matches is True
