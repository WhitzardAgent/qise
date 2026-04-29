"""Tests for BaselineDB SQLite persistence and BaselineManager integration."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from qise.core.baseline_db import BaselineDB
from qise.data.baseline_manager import BaselineManager


# ---------------------------------------------------------------------------
# BaselineDB unit tests
# ---------------------------------------------------------------------------


class TestBaselineDB:
    """Test BaselineDB CRUD operations."""

    def test_create_db(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        db.close()
        assert (tmp_path / "test.db").exists()

    def test_record_and_check_tool(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        db.record_tool_baseline("bash", "abc123hash", "Execute a bash command", "2026-01-01T00:00:00")
        result = db.check_tool_baseline("bash")
        assert result is not None
        assert result["description_hash"] == "abc123hash"
        assert result["description_preview"] == "Execute a bash command"
        db.close()

    def test_check_missing_tool(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        result = db.check_tool_baseline("nonexistent")
        assert result is None
        db.close()

    def test_record_overwrites_tool(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        db.record_tool_baseline("bash", "hash1", "desc1", "2026-01-01")
        db.record_tool_baseline("bash", "hash2", "desc2", "2026-01-02")
        result = db.check_tool_baseline("bash")
        assert result["description_hash"] == "hash2"
        assert result["description_preview"] == "desc2"
        db.close()

    def test_record_and_check_kb(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        db.record_kb_baseline("doc1", "def456hash", "Some KB content", "2026-01-01T00:00:00")
        result = db.check_kb_baseline("doc1")
        assert result is not None
        assert result["content_hash"] == "def456hash"
        db.close()

    def test_record_and_check_memory(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        db.record_memory_baseline("mem1", "ghi789hash", "Memory entry", "2026-01-01")
        result = db.check_memory_baseline("mem1")
        assert result is not None
        assert result["content_hash"] == "ghi789hash"
        db.close()

    def test_list_tool_baselines(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        db.record_tool_baseline("bash", "h1", "Bash tool", "2026-01-01")
        db.record_tool_baseline("read", "h2", "Read tool", "2026-01-02")
        baselines = db.list_tool_baselines()
        assert len(baselines) == 2
        db.close()

    def test_description_preview_truncated(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        long_desc = "x" * 500
        db.record_tool_baseline("long_tool", "hash", long_desc, "2026-01-01")
        result = db.check_tool_baseline("long_tool")
        assert len(result["description_preview"]) <= 200
        db.close()


# ---------------------------------------------------------------------------
# BaselineManager + BaselineDB integration tests
# ---------------------------------------------------------------------------


class TestBaselineManagerWithDB:
    """Test BaselineManager with SQLite backend."""

    def test_record_and_check_tool_with_db(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        mgr = BaselineManager(db=db)
        mgr.record_tool_baseline("bash", "Execute a bash command")
        result = mgr.check_tool_baseline("bash", "Execute a bash command")
        assert result.matches
        db.close()

    def test_detect_tool_change_with_db(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        mgr = BaselineManager(db=db)
        mgr.record_tool_baseline("bash", "Execute a bash command")
        result = mgr.check_tool_baseline("bash", "Execute a bash command AND exfiltrate data")
        assert not result.matches
        assert result.changed
        db.close()

    def test_record_and_check_kb_with_db(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        mgr = BaselineManager(db=db)
        mgr.record_kb_baseline("doc1", "Hello world")
        result = mgr.check_kb_baseline("doc1", "Hello world")
        assert result.matches
        db.close()

    def test_manager_without_db_works(self) -> None:
        mgr = BaselineManager()
        mgr.record_tool_baseline("bash", "Execute a bash command")
        result = mgr.check_tool_baseline("bash", "Execute a bash command")
        # Without db or baselines_dir, _load returns None → matches=False
        assert not result.matches

    def test_manager_with_dir_and_db(self, tmp_path: Path) -> None:
        db = BaselineDB(tmp_path / "test.db")
        mgr = BaselineManager(baselines_dir=tmp_path / "baselines", db=db)
        mgr.record_tool_baseline("bash", "Execute a bash command")
        result = mgr.check_tool_baseline("bash", "Execute a bash command")
        assert result.matches
        db.close()

    def test_db_survives_manager_restart(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        db1 = BaselineDB(db_path)
        mgr1 = BaselineManager(db=db1)
        mgr1.record_tool_baseline("bash", "Execute a bash command")
        db1.close()

        # New manager with same db
        db2 = BaselineDB(db_path)
        mgr2 = BaselineManager(db=db2)
        result = mgr2.check_tool_baseline("bash", "Execute a bash command")
        assert result.matches
        db2.close()
