"""Append-only audit log in SQLite. Layer 7 (visibility); the dashboard timeline reads from here.
Invariant: events are only inserted, never updated or deleted. Every gateway step is logged via Gateway.emit().
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path


class AuditLog:
    def __init__(self, db_path: Path | str):
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, kind TEXT NOT NULL, "
            "action_id TEXT, data TEXT NOT NULL, screenshot_ref TEXT)"
        )
        self._db.commit()

    def log(self, event: dict) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO events (ts, kind, action_id, data, screenshot_ref) VALUES (?,?,?,?,?)",
                (event["ts"], event["kind"], event.get("action_id"),
                 json.dumps(event.get("data", {}), default=str), event.get("screenshot_ref")),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def list(self, since_id: int = 0, limit: int = 500) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ts, kind, action_id, data, screenshot_ref FROM events "
                "WHERE id > ? ORDER BY id DESC LIMIT ?", (since_id, limit)
            ).fetchall()
        rows.reverse()
        return [
            {"id": r[0], "ts": r[1], "kind": r[2], "action_id": r[3], "data": json.loads(r[4]), "screenshot_ref": r[5]}
            for r in rows
        ]
