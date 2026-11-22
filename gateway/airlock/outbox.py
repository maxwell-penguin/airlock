"""Simulated outbox: where an approved send_message lands. Layer 7 (visibility). NOTHING here is ever sent anywhere.

Written by the gateway on the host, after approval, never from inside the sandbox container: an untrusted container
must not be able to write or forge "what was sent". The container does not mount this folder.
Invariants: only validated fields are written (tools.parse_message); a denied, timed-out, rejected or blocked
message writes nothing; rewind does not touch it (it models something that already left the sandbox).
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .models import utc_now


class Outbox:
    def __init__(self, directory: Path):
        self.path = Path(directory) / "outbox.jsonl"
        self._lock = threading.Lock()

    def deliver(self, action_id: str, msg: dict) -> dict:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            entry = {"id": f"m{len(self._read()) + 1:04d}", "ts": utc_now(), "action_id": action_id,
                     "to": msg["to"], "subject": msg["subject"], "body": msg["body"], "simulated": True}
            with self.path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return entry

    def _read(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def list(self) -> list[dict]:
        with self._lock:
            return self._read()

    def clear(self) -> None:
        with self._lock:
            self.path.unlink(missing_ok=True)
