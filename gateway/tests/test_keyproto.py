import hashlib
import hmac
import json

from airlock import keyproto as kp


def test_display_text_truncates_and_sanitizes():
    assert kp.display_text("Open http://a.b") == "Open http://a.b"
    long = kp.display_text("x" * 200)
    assert len(long) == kp.SUMMARY_MAX and long.endswith("~")
    assert kp.display_text("café\nbar") == "caf? bar"


def test_reply_signature_roundtrip():
    shown = kp.display_text("Send message to bob")
    mac = kp.sign_reply("s3cret", "a1", "approve", "n0nce", shown)
    assert kp.verify_reply("s3cret", mac, "a1", "approve", "n0nce", shown)


def test_reply_rejects_tampering():
    shown = "Send message to bob"
    mac = kp.sign_reply("s3cret", "a1", "approve", "n0nce", shown)
    assert not kp.verify_reply("other", mac, "a1", "approve", "n0nce", shown)       # wrong secret
    assert not kp.verify_reply("s3cret", mac, "a1", "deny", "n0nce", shown)         # decision flipped
    assert not kp.verify_reply("s3cret", mac, "a2", "approve", "n0nce", shown)      # other action
    assert not kp.verify_reply("s3cret", mac, "a1", "approve", "n0nce", "Send message to eve")  # text differs
    assert not kp.verify_reply("s3cret", None, "a1", "approve", "n0nce", shown)


def test_matches_independent_hmac_implementation():
    """Firmware must reproduce this: HMAC-SHA256(secret, 'id|decision|nonce|digest')."""
    shown = "Open http://demo.local/clean.html"
    digest = hashlib.sha256(shown.encode()).hexdigest()[:16]
    expected = hmac.new(b"dev-secret-change-me", f"a1b2c3|approve|9f3c11aa|{digest}".encode(), hashlib.sha256).hexdigest()
    assert kp.sign_reply("dev-secret-change-me", "a1b2c3", "approve", "9f3c11aa", shown) == expected


def test_request_encoding_is_one_json_line():
    line = kp.encode_request("a1", "Send message to bob", "n0nce", 3)
    assert line.endswith("\n") and line.count("\n") == 1
    msg = json.loads(line)
    assert msg == {"type": "request", "action_id": "a1", "summary": "Send message to bob", "nonce": "n0nce", "risk": 3}


def test_decode_line_ignores_garbage():
    assert kp.decode_line(b"selftest: ok\n") is None
    assert kp.decode_line(b"{not json}\n") is None
    assert kp.decode_line(b'{"type":"panic"}\n') == {"type": "panic"}


def test_autonomy_state_encoding_is_one_compact_json_line():
    """The firmware (flatjson test_gateway_autonomy_state) parses exactly this line."""
    assert kp.encode_autonomy_state("autonomous") == '{"type":"autonomy_state","level":"autonomous"}\n'
