"""Small SQLite persistence layer with no sensitive response-body storage."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class Storage:
    """Persist scope snapshots, findings, and lifecycle state locally."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT,
                    confidence TEXT,
                    evidence_json TEXT NOT NULL
                );
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(findings)").fetchall()}
            if "assessment_id" not in columns:
                db.execute("ALTER TABLE findings ADD COLUMN assessment_id TEXT")

    def set_metadata(self, key: str, value: Any) -> None:
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", (key, json.dumps(value)))

    def get_metadata(self, key: str) -> Any | None:
        with self._connect() as db:
            row = db.execute("SELECT value FROM metadata WHERE key = ? LIMIT 1", (key,)).fetchone()
        return json.loads(row["value"]) if row else None

    def add_finding(self, kind: str, status: str, evidence: dict[str, Any], severity: str | None = None, confidence: str | None = None, assessment_id: str | None = None) -> int:
        finding_key = evidence.get("finding_id")
        with self._connect() as db:
            if finding_key and assessment_id:
                rows = db.execute(
                    "SELECT id, evidence_json FROM findings WHERE assessment_id = ? AND kind = ?",
                    (assessment_id, kind),
                ).fetchall()
                for row in rows:
                    try:
                        stored = json.loads(row["evidence_json"])
                        if stored.get("finding_id") == finding_key:
                            db.execute(
                                "UPDATE findings SET status = ?, severity = ?, confidence = ?, evidence_json = ? WHERE id = ?",
                                (status, severity, confidence, json.dumps(evidence), row["id"]),
                            )
                            return int(row["id"])
                    except Exception:
                        pass
            cursor = db.execute(
                "INSERT INTO findings(kind,status,severity,confidence,evidence_json,assessment_id) VALUES (?,?,?,?,?,?)",
                (kind, status, severity, confidence, json.dumps(evidence), assessment_id),
            )
            return int(cursor.lastrowid)


    def list_findings(self, assessment_id: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as db:
            if assessment_id is None:
                rows = db.execute("SELECT id, created_at, kind, status, severity, confidence, evidence_json, assessment_id FROM findings ORDER BY id DESC LIMIT 100").fetchall()
            else:
                rows = db.execute("SELECT id, created_at, kind, status, severity, confidence, evidence_json, assessment_id FROM findings WHERE assessment_id = ? ORDER BY id DESC LIMIT 100", (assessment_id,)).fetchall()
        return [dict(row) | {"evidence": json.loads(row["evidence_json"])} for row in rows]

    def list_audit_events(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return a bounded, structured audit history for reporting."""
        bounded_limit = max(1, min(limit, 1_000))
        with self._connect() as db:
            rows = db.execute("SELECT id, created_at, action, decision, details_json FROM audit_log ORDER BY id LIMIT ?", (bounded_limit,)).fetchall()
        return [dict(row) | {"details": json.loads(row["details_json"])} for row in rows]
