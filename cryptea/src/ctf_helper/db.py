"""SQLite database wrapper for the application."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from .data_paths import db_path
from .logger import configure_logging

_LOG = configure_logging()

SCHEMA_VERSION = 5

BASE_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    project TEXT NOT NULL,
    category TEXT NOT NULL,
    difficulty TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Not Started',
    description TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    favorite INTEGER NOT NULL DEFAULT 0,
    flag TEXT,
    tags TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_type TEXT,
    file_size INTEGER,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (challenge_id) REFERENCES challenges(id) ON DELETE CASCADE
);
"""


class Database:
    """Lightweight SQLite manager with schema migrations."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or db_path()
        self._connection: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        if self._connection is None:
            _LOG.info("Opening database at %s", self.path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(self.path)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys=ON;")
        return self._connection

    @contextmanager
    def cursor(self) -> Iterator[sqlite3.Cursor]:
        conn = self.connect()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    def initialise(self) -> None:
        with self.cursor() as cur:
            cur.executescript(BASE_SQL)
            cur.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", "1"),
            )
            version = self._schema_version(cur)
            if version is None or version < 2:
                self._migrate_to_v2(cur)
                version = 2
            else:
                cur.executescript(SCHEMA_SQL)
            if version < 3:
                self._migrate_to_v3(cur)
            if version < 4:
                self._migrate_to_v4(cur)
            if version < 5:
                self._migrate_to_v5(cur)
            cur.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )

    def clear(self) -> None:
        with self.cursor() as cur:
            cur.execute("DELETE FROM attachments")
            cur.execute("DELETE FROM challenges")

    def close(self) -> None:
        if self._connection is not None:
            _LOG.info("Closing database")
            self._connection.close()
            self._connection = None

    # ------------------------------------------------------------------
    # Schema helpers
    # ------------------------------------------------------------------
    def _schema_version(self, cur: sqlite3.Cursor) -> Optional[int]:
        cur.execute("SELECT value FROM meta WHERE key = 'schema_version'")
        row = cur.fetchone()
        if row is None:
            return None
        try:
            return int(row["value"])
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return None

    def _migrate_to_v2(self, cur: sqlite3.Cursor) -> None:
        _LOG.info("Upgrading database schema to version 2")
        # legacy installs may still have notes table and legacy challenge columns
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='challenges'")
        if cur.fetchone():
            cur.execute("ALTER TABLE challenges RENAME TO challenges_legacy")
        cur.executescript(SCHEMA_SQL)

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='challenges_legacy'")
        if cur.fetchone():
            _LOG.info("Migrating existing challenges to new schema")
            cur.execute(
                """
                INSERT INTO challenges (id, title, project, category, difficulty, status, description, notes, favorite, flag, created_at, updated_at)
                SELECT c.id,
                       c.name,
                       'General',
                       c.category,
                       COALESCE(c.difficulty, 'medium'),
                       'Not Started',
                       c.description,
                       COALESCE(n.markdown, ''),
                       0,
                       c.flag,
                       c.created_at,
                       c.updated_at
                  FROM challenges_legacy AS c
                  LEFT JOIN notes AS n ON n.challenge_id = c.id
                """
            )
            cur.execute("DROP TABLE IF EXISTS challenges_legacy")
        cur.execute("DROP TABLE IF EXISTS notes")
        cur.executescript(SCHEMA_SQL)

    def _migrate_to_v3(self, cur: sqlite3.Cursor) -> None:
        _LOG.info("Upgrading database schema to version 3")
        cur.execute("PRAGMA table_info(challenges)")
        columns = {row[1] for row in cur.fetchall()}
        if "favorite" not in columns:
            cur.execute("ALTER TABLE challenges ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0")
        cur.executescript(SCHEMA_SQL)

    def _migrate_to_v4(self, cur: sqlite3.Cursor) -> None:
        _LOG.info("Upgrading database schema to version 4")
        cur.execute("PRAGMA table_info(challenges)")
        columns = {row[1] for row in cur.fetchall()}
        if "tags" not in columns:
            cur.execute("ALTER TABLE challenges ADD COLUMN tags TEXT NOT NULL DEFAULT ''")
        cur.executescript(SCHEMA_SQL)

    def _migrate_to_v5(self, cur: sqlite3.Cursor) -> None:
        _LOG.info("Upgrading database schema to version 5 - Enhanced attachments")
        
        # Check if attachments table exists and get its columns
        cur.execute("PRAGMA table_info(attachments)")
        columns = {row[1] for row in cur.fetchall()}
        
        if not columns:
            # Table doesn't exist, create it with new schema
            cur.executescript(SCHEMA_SQL)
        else:
            # Table exists, migrate it
            # Check if we have the old schema (stored_path, created_at)
            has_old_schema = "stored_path" in columns or "created_at" in columns
            
            if has_old_schema:
                _LOG.info("Migrating attachments table from old schema")
                # Rename old table
                cur.execute("ALTER TABLE attachments RENAME TO attachments_old")
                
                # Create new table
                cur.execute("""
                    CREATE TABLE attachments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        challenge_id INTEGER NOT NULL,
                        file_name TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_type TEXT,
                        file_size INTEGER,
                        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (challenge_id) REFERENCES challenges(id) ON DELETE CASCADE
                    )
                """)
                
                # Migrate data if old table had data
                cur.execute("SELECT COUNT(*) FROM attachments_old")
                if cur.fetchone()[0] > 0:
                    # Try to migrate data (best effort)
                    try:
                        cur.execute("""
                            INSERT INTO attachments (id, challenge_id, file_name, file_path, added_at)
                            SELECT id, challenge_id, file_name, 
                                   COALESCE(stored_path, file_name),
                                   COALESCE(created_at, CURRENT_TIMESTAMP)
                            FROM attachments_old
                        """)
                        _LOG.info("Migrated attachment records from old schema")
                    except Exception as e:
                        _LOG.warning(f"Could not migrate old attachment data: {e}")
                
                # Drop old table
                cur.execute("DROP TABLE attachments_old")
            else:
                # Add missing columns to existing table
                if "file_type" not in columns:
                    cur.execute("ALTER TABLE attachments ADD COLUMN file_type TEXT")
                if "file_size" not in columns:
                    cur.execute("ALTER TABLE attachments ADD COLUMN file_size INTEGER")
                if "added_at" not in columns:
                    cur.execute("ALTER TABLE attachments ADD COLUMN added_at DATETIME DEFAULT CURRENT_TIMESTAMP")
                # Rename file_path if it was stored_path
                if "stored_path" in columns and "file_path" not in columns:
                    # SQLite doesn't support column rename directly in old versions
                    # We need to recreate the table
                    cur.execute("ALTER TABLE attachments RENAME TO attachments_old")
                    cur.executescript(SCHEMA_SQL)
                    cur.execute("""
                        INSERT INTO attachments (id, challenge_id, file_name, file_path, file_type, file_size, added_at)
                        SELECT id, challenge_id, file_name, stored_path, file_type, file_size, 
                               COALESCE(added_at, CURRENT_TIMESTAMP)
                        FROM attachments_old
                    """)
                    cur.execute("DROP TABLE attachments_old")

