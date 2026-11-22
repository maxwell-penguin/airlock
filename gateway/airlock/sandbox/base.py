"""Sandbox interface. Layers 5 and 6. Every backend (mock, docker, VM, remote machine) implements exec_tool;
snapshots are shared because the workspace is a plain folder on the host.
Invariant: the sandbox only runs actions the gateway has already allowed; it never decides policy.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..models import Action, ToolResult
from ..outbox import Outbox
from ..snapshots import SnapshotStore
from ..tools import parse_message


class Sandbox(ABC):
    def __init__(self, workspace: Path, snapshot_root: Path):
        self.workspace = workspace
        self.store = SnapshotStore(workspace, snapshot_root)
        self.outbox: Outbox | None = None  # set by build_gateway; host-side, never inside a container

    def start(self) -> None:
        """Bring the sandbox up. No-op for the mock."""

    def stop(self) -> None:
        """Tear it down. No-op for the mock."""

    def on_unfreeze(self) -> None:
        """The gateway was unfrozen. A backend that aborted running work on a freeze lets new work start again. No-op for the mock."""

    def deliver_message(self, action: Action) -> ToolResult:
        """send_message is SIMULATED: validated fields go to the host-side outbox, nothing is sent anywhere."""
        if self.outbox is None:
            return ToolResult(ok=False, output="no outbox configured")
        msg, err = parse_message(action.details)
        if msg is None:
            return ToolResult(ok=False, output=f"message rejected: {err}")
        entry = self.outbox.deliver(action.id, msg)
        return ToolResult(output=f"Message {entry['id']} to {msg['to']} saved to the outbox "
                                 "(SIMULATED: nothing was sent to any real service)")

    @abstractmethod
    async def exec_tool(self, action: Action) -> ToolResult:
        ...

    def snapshot(self, label: str = "") -> str:
        return self.store.snapshot(label)

    def restore(self, snapshot_id: str) -> None:
        self.store.restore(snapshot_id)

    def latest_snapshot(self) -> str | None:
        return self.store.latest()

    def list_snapshots(self) -> list[str]:
        return self.store.list()
