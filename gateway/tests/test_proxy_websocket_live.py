"""WebSocket canary scan against a REAL mitmproxy (the same 12.3.1 the compose file pins), on the host, no Docker.

mitmdump runs in reverse mode in front of a local WebSocket server, with proxy/airlock_addon.py loaded, so the real
`websocket_message` hook decides. Skipped unless mitmdump is found (PATH or AIRLOCK_MITMDUMP=/path/to/mitmdump).
NOT covered: the compose proxy container and the sandbox's own network path (that needs `make sandbox-up`).
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

MITMDUMP = os.getenv("AIRLOCK_MITMDUMP") or shutil.which("mitmdump")
pytestmark = pytest.mark.skipif(not MITMDUMP, reason="mitmdump not installed (set AIRLOCK_MITMDUMP)")

ADDON = Path(__file__).resolve().parents[2] / "proxy" / "airlock_addon.py"
CANARY = "sk-live-FAKEcanary0123456789"
GIVE_BACK = "give-me-the-secret"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    from websockets.sync.server import serve
    tmp = tmp_path_factory.mktemp("wslive")
    received, events = [], []

    def handler(ws):
        try:
            for m in ws:
                received.append(m)
                ws.send(CANARY if m == GIVE_BACK else m)  # an echo server that can also be made to send the canary back
        except Exception:
            pass
    echo = serve(handler, "127.0.0.1", 0)
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    echo_port = echo.socket.getsockname()[1]

    class Gw(BaseHTTPRequestHandler):
        def do_POST(self):
            events.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass
    gw = HTTPServer(("127.0.0.1", 0), Gw)
    threading.Thread(target=gw.serve_forever, daemon=True).start()

    canaries = tmp / "canaries.json"
    canaries.write_text(json.dumps({"values": [CANARY]}))
    port = free_port()
    env = dict(os.environ, AIRLOCK_ALLOWLIST="127.0.0.1,localhost", AIRLOCK_CANARY_FILE=str(canaries),
               AIRLOCK_GATEWAY_URL=f"http://127.0.0.1:{gw.server_port}")
    env.pop("AIRLOCK_EXTERNAL_TOKEN", None)
    log = open(tmp / "mitm.log", "w")
    proc = subprocess.Popen([MITMDUMP, "-q", "-s", str(ADDON), "--mode", f"reverse:http://127.0.0.1:{echo_port}",
                             "--listen-host", "127.0.0.1", "--listen-port", str(port), "--set", f"confdir={tmp / 'conf'}"],
                            env=env, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            break
        except OSError:
            if proc.poll() is not None:
                pytest.fail("mitmdump exited: " + (tmp / "mitm.log").read_text()[-800:])
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("mitmdump did not start")
    yield {"url": f"ws://127.0.0.1:{port}/", "received": received, "events": events}
    proc.terminate()
    proc.wait(10)
    echo.shutdown()
    gw.shutdown()


def connect(stack):
    from websockets.sync.client import connect as ws_connect
    return ws_connect(stack["url"], open_timeout=10, close_timeout=2)


def wait_for(cond, secs=5):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def is_cut(ws):
    """After a hit the proxy kills the connection: the next recv raises, whatever we send or wait for."""
    from websockets.exceptions import ConnectionClosed
    try:
        ws.recv(timeout=5)
    except ConnectionClosed:
        return True
    except TimeoutError:
        return False
    return False


def test_clean_messages_pass_both_ways(stack):
    with connect(stack) as ws:
        ws.send("hello")
        assert ws.recv(timeout=5) == "hello"
        ws.send(b"\x00\x01binary")
        assert ws.recv(timeout=5) == b"\x00\x01binary"


@pytest.mark.parametrize("name,msg", [
    ("plain", f"token={CANARY}"),
    ("base64", __import__("base64").b64encode(CANARY.encode()).decode()),
    ("hex", CANARY.encode().hex()),
    ("json-unicode-escapes", '{"k":"\\u0073k-live-FAKEcanary0123456789"}'),
])
def test_a_canary_sent_by_the_sandbox_is_reported_and_the_connection_is_cut(stack, name, msg):
    before, n_events = len(stack["received"]), len(stack["events"])
    with connect(stack) as ws:
        ws.send(msg)
        assert is_cut(ws), name
    assert wait_for(lambda: len(stack["events"]) > n_events), "no report reached the gateway"
    ev = stack["events"][-1]
    assert ev["kind"] == "canary_leak" and "websocket" in ev["detail"] and "client to server" in ev["detail"]
    assert CANARY not in json.dumps(ev)
    assert stack["received"][before:] == [], "the server must never have received the message"


def test_a_canary_split_across_two_messages_is_caught_on_the_second(stack):
    n_events = len(stack["events"])
    with connect(stack) as ws:
        ws.send(CANARY[:12])
        assert ws.recv(timeout=5) == CANARY[:12]           # the first half alone is not a canary
        ws.send(CANARY[12:])
        assert is_cut(ws)
    assert wait_for(lambda: len(stack["events"]) > n_events)
    assert stack["events"][-1]["kind"] == "canary_leak"


def test_a_canary_coming_back_from_the_server_is_caught_too(stack):
    n_events = len(stack["events"])
    with connect(stack) as ws:
        ws.send(GIVE_BACK)                                  # the server answers with the canary
        from websockets.exceptions import ConnectionClosed
        with pytest.raises(ConnectionClosed):
            ws.recv(timeout=5)                              # the message never reaches the client
    assert wait_for(lambda: len(stack["events"]) > n_events)
    assert "server to client" in stack["events"][-1]["detail"]


def test_the_proxy_keeps_serving_new_connections_after_a_cut(stack):
    with connect(stack) as ws:
        ws.send("still works")
        assert ws.recv(timeout=5) == "still works"


def test_a_canary_in_the_close_frame_reason_is_reported(stack):
    n_events = len(stack["events"])
    with connect(stack) as ws:
        ws.send("hello")
        ws.recv(timeout=5)
        ws.close(1000, "bye " + CANARY)                      # a close reason can carry up to 123 bytes
    assert wait_for(lambda: len(stack["events"]) > n_events), "no report reached the gateway"
    assert stack["events"][-1]["kind"] == "canary_leak" and "close frame" in stack["events"][-1]["detail"]


@pytest.mark.xfail(strict=True, reason="KNOWN GAP: mitmproxy has no hook for ping/pong frames, so a canary in a ping payload (up to 125 bytes) is not scanned")
def test_a_canary_in_a_ping_payload_is_caught(stack):
    n_events = len(stack["events"])
    with connect(stack) as ws:
        ws.ping(CANARY.encode()).wait(5)                      # the server pongs; neither frame is ever shown to the addon
        assert wait_for(lambda: len(stack["events"]) > n_events, 2)
