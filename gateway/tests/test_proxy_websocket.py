"""WebSocket canary scan: the pure logic, and the addon's hook with mitmproxy stubbed (no mitmproxy needed).
The real hook against real mitmproxy is tests/test_proxy_websocket_live.py (skipped without mitmdump)."""
import base64
import codecs
import importlib
import json
import sys
import threading
import types
from urllib.parse import quote

import pytest

from proxy.logic import WS_TAIL, decide_ws

VALUES = ["sk-live-FAKEcanary0123456789", "maple-harbor-violet42"]
V = VALUES[0]


# --- the logic -------------------------------------------------------------------------------------------------------------

def hit(payload, prior=b"", from_client=True):
    return decide_ws("example.com", payload if isinstance(payload, bytes) else payload.encode(), prior, VALUES, from_client)


def test_clean_messages_pass_in_both_directions():
    for m in (b"hello", b"", b"\x00\xff\xfe binary", json.dumps({"price": 9, "plan": "pro"}).encode(), b"sk-live-"):
        assert hit(m) is None and hit(m, from_client=False) is None


@pytest.mark.parametrize("form", [
    lambda v: v, lambda v: v[::-1], lambda v: v.encode().hex(), lambda v: codecs.encode(v, "rot13"),
    lambda v: base64.b64encode(v.encode()).decode(), lambda v: base64.b32encode(v.encode()).decode(), lambda v: quote(v, safe=""),
    lambda v: "  ".join(v), lambda v: "-".join(v), lambda v: "​".join(v), lambda v: v.upper(),
    lambda v: json.dumps({"x": v}), lambda v: "".join(f"\\u{ord(c):04x}" for c in v),
])
@pytest.mark.parametrize("value", VALUES)
def test_every_re_encoding_the_tripwire_handles_is_caught_in_a_message(form, value):
    ev = hit("data: " + form(value) + " end")
    assert ev and ev["kind"] == "canary_leak" and ev["host"] == "example.com"


def test_both_directions_are_scanned_and_reported_with_the_direction_and_never_the_value():
    up, down = hit(V), hit(V, from_client=False)
    assert "client to server" in up["detail"] and "server to client" in down["detail"]
    assert V not in json.dumps(up) and V not in json.dumps(down)


def test_a_canary_split_across_two_messages_is_caught_on_the_second():
    assert hit(V[:10]) is None
    assert hit(V[10:], prior=V[:10].encode())["kind"] == "canary_leak"


def test_binary_frames_are_scanned_too():
    assert hit(b"\x00\x01\x02" + V.encode() + b"\xff")["kind"] == "canary_leak"


def test_ordinary_text_is_not_a_false_positive():
    for m in ("The quick brown fox", "sk-live-and-learn", "violet and maple harbor", "x" * 5000, "0123456789abcdef" * 100):
        assert hit(m) is None, m[:30]


# --- the addon hook, mitmproxy stubbed ---------------------------------------------------------------------------------------

@pytest.fixture
def addon(monkeypatch, tmp_path):
    fake_http = types.SimpleNamespace(HTTPFlow=object, Response=types.SimpleNamespace(make=lambda *a, **k: None))
    fake = types.ModuleType("mitmproxy")
    fake.http = fake_http
    killed = []

    class Handler:
        def __init__(self, client):
            self.client = client

        def close_connection(self, connection, half_close=False):
            killed.append(connection)
    client = object()
    fake.ctx = types.SimpleNamespace(master=types.SimpleNamespace(addons=types.SimpleNamespace(
        get=lambda name: types.SimpleNamespace(connections={"c": Handler(client), "other": Handler(object())}))))
    monkeypatch.setitem(sys.modules, "mitmproxy", fake)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", fake_http)
    sys.modules.pop("proxy.airlock_addon", None)
    mod = importlib.import_module("proxy.airlock_addon")
    sent = []

    class Resp:
        def read(self):
            return b"{}"
    monkeypatch.setattr(mod.urllib.request, "urlopen", lambda req, timeout=0: sent.append(json.loads(req.data)) or Resp())
    canaries = tmp_path / "canaries.json"
    canaries.write_text(json.dumps({"values": VALUES}))
    monkeypatch.setenv("AIRLOCK_CANARY_FILE", str(canaries))
    monkeypatch.setenv("AIRLOCK_ALLOWLIST", "example.com")
    monkeypatch.delenv("AIRLOCK_EXTERNAL_TOKEN", raising=False)

    def flush():
        for t in threading.enumerate():
            if t is not threading.current_thread() and t.daemon and t.name.startswith("Thread"):
                t.join(2)

    def make_flow(fid="f1"):
        return types.SimpleNamespace(id=fid, request=types.SimpleNamespace(pretty_host="example.com"), client_conn=client,
                                     websocket=types.SimpleNamespace(messages=[]))

    def send(a, flow, content, from_client=True):
        msg = types.SimpleNamespace(content=content, from_client=from_client, dropped=False)
        msg.drop = lambda: setattr(msg, "dropped", True)
        flow.websocket.messages.append(msg)
        a.websocket_message(flow)
        return msg
    return types.SimpleNamespace(mod=mod, a=mod.Airlock(), sent=sent, killed=killed, client=client, flush=flush, flow=make_flow, send=send)


def test_a_clean_message_is_untouched(addon):
    f = addon.flow()
    m = addon.send(addon.a, f, b"hello")
    addon.flush()
    assert not m.dropped and addon.sent == [] and addon.killed == []


def test_a_canary_message_is_dropped_reported_and_the_connection_is_closed(addon):
    f = addon.flow()
    m = addon.send(addon.a, f, f"k={V}".encode())
    addon.flush()
    assert m.dropped and addon.killed == [addon.client]                 # only the offending client's connection
    assert [e["kind"] for e in addon.sent] == ["canary_leak"] and V not in json.dumps(addon.sent)


def test_a_canary_from_the_server_is_caught_and_cut_too(addon):
    f = addon.flow()
    m = addon.send(addon.a, f, V.encode(), from_client=False)
    addon.flush()
    assert m.dropped and addon.killed == [addon.client] and "server to client" in addon.sent[0]["detail"]


def test_a_split_canary_is_caught_per_direction_and_the_directions_do_not_mix(addon):
    f = addon.flow()
    assert not addon.send(addon.a, f, V[:10].encode()).dropped
    assert not addon.send(addon.a, f, V[10:].encode(), from_client=False).dropped   # other direction: not a continuation
    assert addon.send(addon.a, f, V[10:].encode()).dropped


def test_if_the_real_cut_fails_every_later_message_on_that_flow_is_still_dropped(addon, monkeypatch):
    monkeypatch.setitem(sys.modules["mitmproxy"].__dict__, "ctx", None)    # ctx.master.addons... raises
    f = addon.flow()
    assert addon.send(addon.a, f, V.encode()).dropped
    later = addon.send(addon.a, f, b"harmless")
    assert later.dropped
    assert not addon.send(addon.a, addon.flow("f2"), b"harmless").dropped   # another connection is unaffected


def test_state_is_cleaned_up_when_the_websocket_ends(addon):
    f = addon.flow()
    addon.send(addon.a, f, b"a" * (WS_TAIL * 2))
    assert addon.a._ws_tail[("f1", True)] == b"a" * WS_TAIL                 # only a bounded tail is kept
    addon.send(addon.a, f, V.encode())
    addon.a.websocket_end(f)
    assert addon.a._ws_tail == {} and addon.a._ws_cut == set()


def test_a_flow_without_websocket_data_is_ignored(addon):
    f = addon.flow()
    f.websocket = None
    addon.a.websocket_message(f)
    f.websocket = types.SimpleNamespace(messages=[])
    addon.a.websocket_message(f)


def test_a_canary_in_the_close_frame_reason_is_reported_even_though_it_was_already_forwarded(addon):
    """mitmproxy forwards a close frame before any hook sees it, so all we can do is report it (the gateway freezes)."""
    f = addon.flow()
    f.websocket.close_reason, f.websocket.closed_by_client = f"bye {V}", True
    addon.a.websocket_end(f)
    addon.flush()
    ev = addon.sent
    assert [e["kind"] for e in ev] == ["canary_leak"] and "close frame" in ev[0]["detail"] and V not in json.dumps(ev)


def test_an_ordinary_close_reason_reports_nothing(addon):
    f = addon.flow()
    f.websocket.close_reason, f.websocket.closed_by_client = "normal closure", False
    addon.a.websocket_end(f)
    f2 = addon.flow("f2")
    f2.websocket.close_reason, f2.websocket.closed_by_client = None, None
    addon.a.websocket_end(f2)
    addon.flush()
    assert addon.sent == []


# --- the known gap, pinned (ping and pong payloads) --------------------------------------------------------------------------
# What is scanned: every text and binary WebSocket message in both directions (websocket_message) and the close-frame reason after the
# fact (websocket_end). What is NOT: ping and pong payloads (up to 125 bytes each). mitmproxy 12.3.1 had no hook for them when this was
# checked live (docs/THREAT_MODEL.md row 66); it was not re-checked offline. These tests do not prove the gap, they pin OUR side of it so a
# change is noticed: if someone adds a ping hook, or the addon starts to read frames some other way, these fail and the docs must follow.

def test_the_addon_hooks_only_messages_and_the_end_of_a_websocket(addon):
    hooks = {n for n in dir(addon.a) if n.startswith(("websocket_", "ping", "pong", "on_ping", "on_pong"))}
    assert hooks == {"websocket_message", "websocket_end"}


def test_a_canary_offered_as_a_ping_payload_is_not_seen_by_any_hook_today(addon):
    f = addon.flow()
    f.websocket.ping_payload, f.websocket.pong_payload = V.encode(), V.encode()    # not a real mitmproxy field: nothing hands us these bytes
    addon.a.websocket_message(f)      # no message: nothing to scan
    addon.a.websocket_end(f)
    addon.flush()
    assert addon.sent == [] and addon.killed == []


def test_the_threat_model_states_the_ping_pong_limit():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] / "docs" / "THREAT_MODEL.md").read_text()
    assert "ping/pong payloads cannot be scanned" in text and "125 bytes" in text
