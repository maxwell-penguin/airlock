"""Wire protocol between the gateway and the hardware approval key (JSON lines over USB serial). Layer 3.

gateway -> key   {"type":"request","action_id","summary","nonce","risk"}
gateway -> key   {"type":"cancel","action_id"}                      (answered elsewhere or timed out: clear the screen)
gateway -> key   {"type":"autonomy_state","level"}                  (display only: the level in force, for the idle screen)
key -> gateway   {"type":"reply","action_id","decision":"approve|deny","digest","hmac"}
key -> gateway   {"type":"panic"}                                   (always accepted: freezing is safe)
key -> gateway   {"type":"autonomy","level","seq","hmac"}           (signed, seq must increase)

"What you see is what you sign": the key hashes the exact text it displayed (digest) and the
HMAC covers that digest, so the gateway can check the key showed the text the gateway sent.
HMAC = HMAC-SHA256(secret, "|".join(parts)), hex lowercase.
INVARIANT: any change here must be matched in firmware/ and docs/CONTRACTS.md, and the test vectors must pass.
"""
from __future__ import annotations

import hashlib
import hmac
import json

SUMMARY_MAX = 84  # at most 3 pages of 32 chars on the key's 16x2 LCD


def display_text(summary: str) -> str:
    """The exact text the key will display (truncated, ASCII-safe)."""
    text = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in summary.replace("\n", " "))
    return text if len(text) <= SUMMARY_MAX else text[: SUMMARY_MAX - 1] + "~"


def digest(text: str) -> str:
    """First 16 hex chars of SHA-256 of the displayed text."""
    return hashlib.sha256(text.encode("ascii", "replace")).hexdigest()[:16]


def sign_parts(secret: str, *parts: object) -> str:
    msg = "|".join(str(p) for p in parts).encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_parts(secret: str, mac: str | None, *parts: object) -> bool:
    return hmac.compare_digest(sign_parts(secret, *parts), (mac or "").lower())


def sign_reply(secret: str, action_id: str, decision: str, nonce: str, shown_text: str) -> str:
    return sign_parts(secret, action_id, decision, nonce, digest(shown_text))


def verify_reply(secret: str, mac: str | None, action_id: str, decision: str, nonce: str, shown_text: str) -> bool:
    return verify_parts(secret, mac, action_id, decision, nonce, digest(shown_text))


def encode_request(action_id: str, summary: str, nonce: str, risk: int) -> str:
    msg = {"type": "request", "action_id": action_id, "summary": display_text(summary), "nonce": nonce, "risk": risk}
    return json.dumps(msg, separators=(",", ":")) + "\n"


def encode_autonomy_state(level: str) -> str:
    """The autonomy level in force, for the key's idle screen. Display only: unsigned, and the key never acts on it or replies."""
    return json.dumps({"type": "autonomy_state", "level": level}, separators=(",", ":")) + "\n"


def decode_line(line: bytes | str) -> dict | None:
    if isinstance(line, bytes):
        line = line.decode("utf-8", "replace")
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return None
    return msg if isinstance(msg, dict) else None
