"""Challenge management and persistence."""

from __future__ import annotations

import base64
import importlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol

from ..data_paths import user_config_dir
from ..db import Database
from ..logger import configure_logging
from .models import Challenge

_LOG = configure_logging()

try:  # pragma: no cover - optional dependency
    nacl_pwhash = importlib.import_module("nacl.pwhash")
    nacl_secret = importlib.import_module("nacl.secret")
    nacl_utils = importlib.import_module("nacl.utils")
except ImportError:  # pragma: no cover - optional dependency
    secret = None  # type: ignore[assignment]
    pwhash = None  # type: ignore[assignment]
    utils = None  # type: ignore[assignment]
else:
    pwhash = nacl_pwhash
    secret = nacl_secret
    utils = nacl_utils

STATUSES = ("Not Started", "In Progress", "Completed")


class PassphraseProvider(Protocol):
    def __call__(self) -> Optional[str]:
        ...


@dataclass(slots=True)
class EncryptionState:
    enabled: bool
    reason: Optional[str] = None


@dataclass(slots=True)
class ProjectProgress:
    project: str
    total: int
    completed: int
    in_progress: int

    @property
    def completion_ratio(self) -> float:
        if self.total == 0:
            return 0.0
        return self.completed / self.total


class ChallengeManager:
    """High-level API over the challenge database."""

    def __init__(self, database: Optional[Database] = None, passphrase_provider: Optional[PassphraseProvider] = None) -> None:
        self.db = database or Database()
        self.db.initialise()
        self.passphrase_provider = passphrase_provider
        self._encryption_key: Optional[bytes] = None
        self._encryption_state = EncryptionState(enabled=False)

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------
    def enable_encryption(self) -> EncryptionState:
        if secret is None or pwhash is None or utils is None:
            self._encryption_state = EncryptionState(
                enabled=False,
                reason="PyNaCl not available; install it to enable flag encryption.",
            )
            return self._encryption_state

        if self.passphrase_provider is None:
            self._encryption_state = EncryptionState(
                enabled=False,
                reason="No passphrase provider configured",
            )
            return self._encryption_state

        phrase = self.passphrase_provider()
        if not phrase:
            self._encryption_state = EncryptionState(
                enabled=False,
                reason="Empty passphrase provided",
            )
            return self._encryption_state

        config_path = self._encryption_config_path()
        if config_path.exists():
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            salt = base64.urlsafe_b64decode(payload["salt"])
        else:
            salt = utils.random(pwhash.argon2id.SALTBYTES)
            config_path.write_text(json.dumps({"salt": base64.urlsafe_b64encode(salt).decode("ascii")}), encoding="utf-8")
        key = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE, phrase.encode("utf-8"), salt)
        self._encryption_key = key
        self._encryption_state = EncryptionState(enabled=True)
        return self._encryption_state

    def encryption_state(self) -> EncryptionState:
        return self._encryption_state

    def _derive_box(self) -> Optional[Any]:
        if not self._encryption_key or secret is None:
            return None
        return secret.SecretBox(self._encryption_key)

    def _encryption_config_path(self) -> Path:
        return user_config_dir() / "encryption.json"

    def _encrypt_flag(self, flag: Optional[str]) -> Optional[str]:
        if flag is None:
            return None
        if secret is None or utils is None:
            return flag
        box = self._derive_box()
        if box is None:
            return flag
        nonce = utils.random(secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(flag.encode("utf-8"), nonce)
        blob = base64.urlsafe_b64encode(nonce + encrypted.ciphertext).decode("ascii")
        return f"ENCv1:{blob}"

    def _decrypt_flag(self, value: Optional[str]) -> Optional[str]:
        if value is None or not value.startswith("ENCv1:"):
            return value
        if secret is None:
            return None
        box = self._derive_box()
        if box is None:
            return None
        blob = base64.urlsafe_b64decode(value.split(":", 1)[1])
        nonce = blob[: secret.SecretBox.NONCE_SIZE]
        ciphertext = blob[secret.SecretBox.NONCE_SIZE :]
        plain = box.decrypt(ciphertext, nonce)
        return plain.decode("utf-8")

    # ------------------------------------------------------------------
    # Challenge operations
    # ------------------------------------------------------------------
    def list_challenges(
        self,
        *,
        search: Optional[str] = None,
        project: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        order_by: str = "updated_at DESC",
    ) -> List[Challenge]:
        sql = (
            "SELECT id, title, project, category, difficulty, status, description, notes, flag, created_at, updated_at "
            "FROM challenges WHERE 1=1"
        )
        params: List[str] = []
        if search:
            like = f"%{search.lower()}%"
            sql += " AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(project) LIKE ?)"
            params.extend([like, like, like])
        if project:
            sql += " AND project = ?"
            params.append(project)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if category:
            sql += " AND category = ?"
            params.append(category)
        if order_by not in {"created_at ASC", "created_at DESC", "updated_at ASC", "updated_at DESC", "title COLLATE NOCASE"}:
            order_by = "updated_at DESC"
        sql += f" ORDER BY {order_by}"
        with self.db.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return [self._row_to_challenge(row) for row in rows]

    def list_projects(self) -> List[str]:
        with self.db.cursor() as cur:
            cur.execute("SELECT DISTINCT project FROM challenges ORDER BY LOWER(project)")
            rows = [row[0] for row in cur.fetchall()]
        return rows

    def project_progress(self) -> List[ProjectProgress]:
        with self.db.cursor() as cur:
            cur.execute(
                """
                SELECT project,
                       COUNT(*) AS total,
                       SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
                       SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) AS active
                  FROM challenges
              GROUP BY project
              ORDER BY LOWER(project)
                """
            )
            rows = cur.fetchall()
        return [
            ProjectProgress(
                project=row["project"],
                total=row["total"],
                completed=row["completed"] or 0,
                in_progress=row["active"] or 0,
            )
            for row in rows
        ]

    def active_challenges(self, limit: int = 5) -> List[Challenge]:
        with self.db.cursor() as cur:
            cur.execute(
                """
                SELECT id, title, project, category, difficulty, status, description, notes, flag, created_at, updated_at
                  FROM challenges
                 WHERE status = 'In Progress'
              ORDER BY updated_at DESC
                 LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [self._row_to_challenge(row) for row in rows]

    def create_challenge(
        self,
        *,
        title: str,
        project: str,
        category: str,
        difficulty: str = "medium",
        status: str = "Not Started",
        description: str = "",
        notes: str = "",
        flag: Optional[str] = None,
    ) -> Challenge:
        if status not in STATUSES:
            status = "Not Started"
        now = datetime.now(UTC).isoformat()
        stored_flag = self._encrypt_flag(flag)
        with self.db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO challenges (title, project, category, difficulty, status, description, notes, flag, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, project, category, difficulty, status, description, notes, stored_flag, now, now),
            )
            challenge_id = cur.lastrowid
        if challenge_id is None:  # pragma: no cover - defensive
            raise RuntimeError("Failed to create challenge")
        return self.get_challenge(int(challenge_id))

    def update_challenge(self, challenge_id: int, **fields: str) -> Challenge:
        if not fields:
            return self.get_challenge(challenge_id)
        allowed = {"title", "project", "category", "difficulty", "status", "description", "notes"}
        assignments: List[str] = []
        values: List[str] = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            if key == "status" and value not in STATUSES:
                continue
            assignments.append(f"{key} = ?")
            values.append(value)
        if not assignments:
            return self.get_challenge(challenge_id)
        values.append(datetime.now(UTC).isoformat())
        values.append(str(challenge_id))
        sql = f"UPDATE challenges SET {', '.join(assignments)}, updated_at = ? WHERE id = ?"
        with self.db.cursor() as cur:
            cur.execute(sql, values)
        return self.get_challenge(challenge_id)

    def set_flag(self, challenge_id: int, flag: Optional[str]) -> Challenge:
        stored = self._encrypt_flag(flag)
        with self.db.cursor() as cur:
            cur.execute(
                "UPDATE challenges SET flag = ?, updated_at = ? WHERE id = ?",
                (stored, datetime.now(UTC).isoformat(), challenge_id),
            )
        return self.get_challenge(challenge_id)

    def get_flag(self, challenge_id: int) -> Optional[str]:
        with self.db.cursor() as cur:
            cur.execute("SELECT flag FROM challenges WHERE id = ?", (challenge_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return self._decrypt_flag(row[0])

    def get_challenge(self, challenge_id: int) -> Challenge:
        with self.db.cursor() as cur:
            cur.execute(
                """
                SELECT id, title, project, category, difficulty, status, description, notes, flag, created_at, updated_at
                  FROM challenges
                 WHERE id = ?
                """,
                (challenge_id,),
            )
            row = cur.fetchone()
        if row is None:
            msg = f"Challenge {challenge_id} not found"
            raise ValueError(msg)
        return self._row_to_challenge(row)

    def delete_challenge(self, challenge_id: int) -> None:
        with self.db.cursor() as cur:
            cur.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))

    def notes_for_challenge(self, challenge_id: int) -> str:
        with self.db.cursor() as cur:
            cur.execute("SELECT notes FROM challenges WHERE id = ?", (challenge_id,))
            row = cur.fetchone()
        if row is None:
            return ""
        return row[0] or ""

    def save_note(self, challenge_id: int, markdown: str) -> Challenge:
        return self.update_challenge(challenge_id, notes=markdown)

    def save_notes(self, challenge_id: int, markdown: str) -> Challenge:
        return self.save_note(challenge_id, markdown)

    # ------------------------------------------------------------------
    # Export/import
    # ------------------------------------------------------------------
    def export_all(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for challenge in self.list_challenges(order_by="title COLLATE NOCASE"):
            entries.append(
                {
                    "id": challenge.id,
                    "title": challenge.title,
                    "project": challenge.project,
                    "category": challenge.category,
                    "difficulty": challenge.difficulty,
                    "status": challenge.status,
                    "description": challenge.description,
                    "notes": challenge.notes,
                    "created_at": challenge.created_at.isoformat(),
                    "updated_at": challenge.updated_at.isoformat(),
                    "flag": self.get_flag(challenge.id),
                }
            )
        return entries

    def import_from(self, entries: Iterable[Dict[str, Any]]) -> List[Challenge]:
        imported: List[Challenge] = []
        for entry in entries:
            notes_value: Any = entry.get("notes")
            if notes_value is None:
                legacy_note = entry.get("note")
                if isinstance(legacy_note, dict):
                    notes_value = legacy_note.get("markdown", "")
                else:
                    notes_value = ""
            challenge = self.create_challenge(
                title=entry.get("title") or entry.get("name", "Untitled"),
                project=entry.get("project", "General"),
                category=entry.get("category", "misc"),
                difficulty=entry.get("difficulty", "medium"),
                status=entry.get("status", "Not Started"),
                description=entry.get("description", ""),
                notes=str(notes_value or ""),
            )
            flag = entry.get("flag")
            if flag:
                self.set_flag(challenge.id, flag)
            imported.append(self.get_challenge(challenge.id))
        return imported

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _row_to_challenge(self, row: sqlite3.Row) -> Challenge:
        return Challenge(
            id=row["id"],
            title=row["title"],
            project=row["project"],
            category=row["category"],
            difficulty=row["difficulty"],
            status=row["status"],
            description=row["description"],
            notes=row["notes"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            flag=self._decrypt_flag(row["flag"]),
        )


__all__ = [
    "ChallengeManager",
    "EncryptionState",
    "ProjectProgress",
]
