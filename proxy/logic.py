"""Pure decision logic for the egress proxy (no mitmproxy import, so it is unit-testable)."""
from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
from urllib.parse import quote, unquote


def host_allowed(host: str, allowlist: list[str]) -> bool:
    host = host.lower()
    return any(host == a or host.endswith("." + a) for a in allowlist)


# --- canary detection that survives re-encoding. SAME CODE as gateway/airlock/tripwire.py (this container cannot import the
# gateway); gateway/tests/test_redteam.py::test_gateway_and_proxy_canary_matchers_agree keeps the two in step. ---------------
MIN_NEEDLE = 8


def norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", text).casefold())


def _b64_needles(raw: bytes) -> list[str]:
    out = []
    for k, skip in ((0, 0), (1, 2), (2, 3)):
        enc = base64.b64encode(b"\0" * k + raw).decode().rstrip("=")
        if (k + len(raw)) % 3:
            enc = enc[:-1]
        out.append(enc[skip:])
    return out


_ESC = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}|\\[uU]([0-9a-fA-F]{8}|[0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|%u([0-9a-fA-F]{4})")


def _unescape(text: str) -> str:
    """Undo \\uXXXX, \\UXXXXXXXX, \\u{X}, \\xNN and %uXXXX: a way to spell any letter in JSON, JavaScript and URLs."""
    def one(m):
        code = int(next(g for g in m.groups() if g), 16)
        return chr(code) if code <= 0x10FFFF else ""
    return _ESC.sub(one, text)


def needles(value: str) -> set[str]:
    raw = value.encode()
    forms = [value, value[::-1], raw.hex(), codecs.encode(value, "rot13"), base64.b32encode(raw).decode(), quote(value, safe="")]
    forms += _b64_needles(raw) + _b64_needles(value[::-1].encode())
    return {n for n in (norm(f) for f in forms) if len(n) >= MIN_NEEDLE}


def canary_hits(parts: list[bytes | str], values: list[str]) -> list[str]:
    """Canary values in these request parts (url, headers, body): plain, hex/base64/base32/percent/rot13/reversed, with
    separators or zero-width characters inserted, or split across adjacent parts."""
    joined = "".join(p.decode("utf-8", "replace") if isinstance(p, bytes) else p for p in parts)
    hay = [norm(joined), norm(unquote(joined)), norm(unquote(unquote(joined))), norm(html.unescape(joined)), norm(_unescape(joined))]
    return [v for v in values if v and any(n in h for n in needles(v) for h in hay)]


def find_canaries(parts: list[bytes | str], values: list[str]) -> list[str]:
    return canary_hits(parts, values)


WS_TAIL = 1024  # bytes of the previous message (same direction) kept, so a canary split across two messages is still seen


def decide_ws(host: str, payload: bytes, prior: bytes, canaries: list[str], from_client: bool) -> dict | None:
    """A WebSocket message, either direction. `prior` is the tail of the previous message in the same direction. Same matcher as HTTP,
    (which also undoes \\uXXXX style escapes). Returns the event to report (and cut the
    connection for), or None."""
    text = (prior + payload).decode("utf-8", "replace")
    hits = find_canaries([text], canaries)
    if hits:
        way = "client to server" if from_client else "server to client"
        return {"kind": "canary_leak", "host": host, "detail": f"{len(hits)} canary value(s) in a websocket message ({way})"}
    return None


def decide(host: str, url: str, headers_text: str, body: bytes, allowlist: list[str],
           canaries: list[str]) -> dict | None:
    """Returns an event dict to report (and block the request), or None to let it through.

    Canary check comes first and applies to allowlisted hosts too: a canary leaving the sandbox
    is the worst case wherever it is going.
    """
    hits = find_canaries([url, headers_text, body], canaries)
    if hits:
        return {"kind": "canary_leak", "host": host, "detail": f"{len(hits)} canary value(s) in outbound request"}
    if not host_allowed(host, allowlist):
        return {"kind": "egress_blocked", "host": host, "detail": f"{host} is not on the allowlist"}
    return None
