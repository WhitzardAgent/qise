"""BaselineDB — SQLite persistence for baseline hash records.

Provides durable storage for tool/KB/memory baselines so they survive
restarts.  Used as an optional backend by BaselineManager.

When no BaselineDB is provided, BaselineManager falls back to YAML files
(in-memory if no baselines_dir is set either).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


class BaselineDB:
    """SQLite-backed baseline storage."""

    def __init__(self, db_path: str | Path = "~/.qise/baselines.db") -> None:
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS tool_baselines (
                tool_name TEXT PRIMARY KEY,
                description_hash TEXT NOT NULL,
                description_preview TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS kb_baselines (
                doc_id TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                content_preview TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS memory_baselines (
                entry_id TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                content_preview TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Tool baselines
    # ------------------------------------------------------------------

    def record_tool_baseline(self, tool_name: str, description_hash: str, description_preview: str, recorded_at: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO tool_baselines (tool_name, description_hash, description_preview, recorded_at) VALUES (?, ?, ?, ?)",
            (tool_name, description_hash, description_preview[:200], recorded_at),
        )
        self._conn.commit()

    def check_tool_baseline(self, tool_name: str) -> dict | None:
        row = self._conn.execute(
            "SELECT description_hash, description_preview, recorded_at FROM tool_baselines WHERE tool_name = ?",
            (tool_name,),
        ).fetchone()
        return dict(row) if row else None

    def list_tool_baselines(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM tool_baselines ORDER BY recorded_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # KB baselines
    # ------------------------------------------------------------------

    def record_kb_baseline(self, doc_id: str, content_hash: str, content_preview: str, recorded_at: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO kb_baselines (doc_id, content_hash, content_preview, recorded_at) VALUES (?, ?, ?, ?)",
            (doc_id, content_hash, content_preview[:200], recorded_at),
        )
        self._conn.commit()

    def check_kb_baseline(self, doc_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT content_hash, content_preview, recorded_at FROM kb_baselines WHERE doc_id = ?",
            (doc_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_kb_baselines(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM kb_baselines ORDER BY recorded_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Memory baselines
    # ------------------------------------------------------------------

    def record_memory_baseline(self, entry_id: str, content_hash: str, content_preview: str, recorded_at: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO memory_baselines (entry_id, content_hash, content_preview, recorded_at) VALUES (?, ?, ?, ?)",
            (entry_id, content_hash, content_preview[:200], recorded_at),
        )
        self._conn.commit()

    def check_memory_baseline(self, entry_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT content_hash, content_preview, recorded_at FROM memory_baselines WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_memory_baselines(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM memory_baselines ORDER BY recorded_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()
