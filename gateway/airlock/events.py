"""In-process event bus feeding the dashboard WebSocket. Layer 7. Safe to publish from any thread.
Invariant: a slow subscriber drops events; it never blocks the gateway. The audit log, not the bus, is the record.
"""
from __future__ import annotations

import asyncio


class EventBus:
    def __init__(self) -> None:
        self._queues: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._queues.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._queues.discard(q)

    def _fanout(self, event: dict) -> None:
        for q in list(self._queues):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # slow dashboard: drop rather than block the gateway

    def publish(self, event: dict) -> None:
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._fanout, event)
        else:
            self._fanout(event)
