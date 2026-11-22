import asyncio
import socket
import threading
import time
import types
from pathlib import Path

import pytest

from airlock.approvals import MockChannel
from airlock.build import build_gateway
from airlock.config import REPO_DIR, Settings


@pytest.fixture
def make_gw(tmp_path):
    counter = {"n": 0}

    def _make(decision="approve", protect=True, autonomy="balanced", timeout=2.0, delay=0.0):
        counter["n"] += 1
        settings = Settings(state_dir=tmp_path / f"state{counter['n']}", protect=protect, autonomy=autonomy,
                            approval_timeout=timeout, pages_dir=REPO_DIR / "demo" / "pages")
        return build_gateway(settings, extra_channels=[MockChannel(decision, delay)])

    return _make


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def live_gateway(tmp_path):
    """The real FastAPI app under uvicorn on a free local port (for tests that need real HTTP, e.g. the hook script)."""
    import uvicorn

    from airlock.server import create_app
    started = []

    def _start(decision="approve", delay=0.0, timeout=5.0, extra_channels=None, **settings_kw):
        s = Settings(state_dir=tmp_path / f"live{len(started)}", approval_timeout=timeout,
                     pages_dir=REPO_DIR / "demo" / "pages", **settings_kw)
        channels = extra_channels if extra_channels is not None else [MockChannel(decision, delay)]
        gw = build_gateway(s, extra_channels=channels)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(create_app(s, gw), host="127.0.0.1", port=port, log_level="warning"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        for _ in range(200):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started, "test gateway did not start"
        started.append((server, thread))
        return types.SimpleNamespace(url=f"http://127.0.0.1:{port}", port=port, gw=gw, settings=s)

    yield _start
    for server, thread in started:
        server.should_exit = True
        thread.join(5)
