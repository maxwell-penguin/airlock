"""mitmproxy addon: allowlist + canary scan on every outbound request (and on the CONNECT that opens an HTTPS tunnel).

Run (inside the proxy container): mitmdump -s /addon/airlock_addon.py --listen-port 8080
Run against live mitmproxy 12.3.1 (allowlist block, canary_leak incl. HTTPS, event POSTs); the decision logic in
logic.py is also unit-tested. WebSocket messages (both directions) get the same canary scan, see websocket_message.
"""
import json
import os
import sys
import threading
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from logic import WS_TAIL, decide, decide_ws  # noqa: E402

from mitmproxy import http  # noqa: E402  (only available inside mitmproxy)


class Airlock:
    def __init__(self):
        raw = os.getenv("AIRLOCK_ALLOWLIST", "example.com,localhost")
        self.allowlist = [h.strip().lower() for h in raw.split(",") if h.strip()]
        self.canary_file = Path(os.getenv("AIRLOCK_CANARY_FILE", "/state/canaries.json"))
        self.gateway_url = os.getenv("AIRLOCK_GATEWAY_URL", "http://host.docker.internal:8000")
        self.token = os.getenv("AIRLOCK_EXTERNAL_TOKEN", "")  # the gateway's machine token, if it requires one
        self._mtime = 0.0
        self._values: list[str] = []
        self._ws_tail: dict[tuple, bytes] = {}  # (flow id, from_client) -> end of the previous message
        self._ws_cut: set[str] = set()          # flows we cut: if the real cut failed, every later message is still dropped

    def _canaries(self) -> list[str]:
        try:
            mtime = self.canary_file.stat().st_mtime
            if mtime != self._mtime:
                self._values = json.loads(self.canary_file.read_text())["values"]
                self._mtime = mtime
        except (OSError, ValueError, KeyError):
            pass
        return self._values

    def _report(self, event: dict) -> None:
        def post():
            try:
                headers = {"Content-Type": "application/json"}
                if self.token:
                    headers["X-Airlock-Token"] = self.token
                req = urllib.request.Request(
                    f"{self.gateway_url}/internal/proxy-event", data=json.dumps(event).encode(),
                    headers=headers, method="POST")
                urllib.request.urlopen(req, timeout=2).read()
            except Exception:
                pass  # never let reporting break the block itself
        threading.Thread(target=post, daemon=True).start()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """HTTPS starts with CONNECT host:port. Decide HERE, before mitmproxy resolves the name or connects upstream: without this a
        refused host was still looked up (DNS) and handshaken with, so a hostname could carry data out and the refusal came late.
        Only ports 80 and 443 are tunnelled: another port could carry a protocol the scan cannot read."""
        req = flow.request
        event = decide(req.pretty_host, req.pretty_url, str(req.headers), b"", self.allowlist, self._canaries())
        if event is None and req.port not in (80, 443):
            event = {"kind": "egress_blocked", "host": req.pretty_host, "detail": f"port {req.port} is not allowed through the proxy"}
        if event:
            self._report(event)
            flow.response = http.Response.make(403, b"Blocked by Airlock", {"Content-Type": "text/plain"})

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        event = decide(req.pretty_host, req.pretty_url, str(req.headers),
                       req.get_content(strict=False) or b"", self.allowlist, self._canaries())
        if event:
            self._report(event)
            flow.response = http.Response.make(403, b"Blocked by Airlock", {"Content-Type": "text/plain"})

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Every WebSocket message, both directions, gets the same canary scan as HTTP bodies. A hit is reported (the gateway
        freezes) and the message is dropped and the connection killed: nothing after it gets through either."""
        if flow.websocket is None or not flow.websocket.messages:
            return
        msg = flow.websocket.messages[-1]
        if flow.id in self._ws_cut:
            msg.drop()
            return
        key = (flow.id, msg.from_client)
        content = msg.content or b""
        event = decide_ws(flow.request.pretty_host, content, self._ws_tail.get(key, b""), self._canaries(), msg.from_client)
        if event:
            self._report(event)
            msg.drop()
            self._cut(flow)
            self._ws_tail.pop(key, None)
        else:
            self._ws_tail[key] = (self._ws_tail.get(key, b"") + content)[-WS_TAIL:]

    def _cut(self, flow: http.HTTPFlow) -> None:
        """Close the client's connection (and with it the server side). flow.kill() cannot do this for a flow that is already
        in transit (mitmproxy issue 4711), so we ask the proxy server's own connection handler to close it. That is mitmproxy
        internals, checked against the pinned 12.3.1 only; if it ever fails, every later message on this flow is dropped
        instead (the connection stays open but carries nothing)."""
        self._ws_cut.add(flow.id)
        try:
            from mitmproxy import ctx
            for handler in list(ctx.master.addons.get("proxyserver").connections.values()):
                if handler.client is flow.client_conn:
                    handler.close_connection(handler.client, half_close=False)
        except Exception:
            pass

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        """A close frame carries a reason of up to 123 bytes, and mitmproxy forwards it BEFORE any hook runs, so it can only be reported
        after the fact (the gateway freezes). Ping and pong payloads (up to 125 bytes) have no hook at all: a known gap."""
        ws = flow.websocket
        reason = getattr(ws, "close_reason", None) if ws is not None else None
        if reason:
            raw = reason if isinstance(reason, bytes) else str(reason).encode("utf-8", "replace")
            event = decide_ws(flow.request.pretty_host, raw, b"", self._canaries(), bool(getattr(ws, "closed_by_client", False)))
            if event:
                event["detail"] += "; in the close frame, which was already forwarded"
                self._report(event)
        self._ws_cut.discard(flow.id)
        for from_client in (True, False):
            self._ws_tail.pop((flow.id, from_client), None)


addons = [Airlock()]
