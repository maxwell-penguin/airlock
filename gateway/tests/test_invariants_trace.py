"""Direct tests for invariants in CLAUDE.md that had no test of their own (see docs/INVARIANTS.md)."""
from pathlib import Path

from airlock import keyproto as kp

ROOT = Path(__file__).resolve().parents[2]
SECRET, SHOWN = "dev-secret-change-me", "Open http://demo.local/clean.html"


def test_the_keyproto_vectors_in_the_contract_and_the_firmware_test_match_the_python_output():
    """A change to keyproto.py that is not matched in docs/CONTRACTS.md and firmware/ breaks this. The firmware test itself needs
    PlatformIO and was NOT run here; this only checks that its copy of the vectors is the same as the Python output."""
    reply = kp.sign_reply(SECRET, "a1b2c3", "approve", "9f3c11aa", SHOWN)
    auto = kp.sign_parts(SECRET, "autonomy", "autonomous", 1)
    digest = reply and __import__("hashlib").sha256(SHOWN.encode()).hexdigest()[:16]
    contract = (ROOT / "docs" / "CONTRACTS.md").read_text()
    firmware = (ROOT / "firmware" / "test" / "test_keylogic" / "test_main.cpp").read_text()
    for value in (digest, reply, auto):
        assert value in contract, value
    assert reply in firmware and auto in firmware
