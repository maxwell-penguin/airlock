"""Smoke test for the approval key, run against real hardware.

    cd gateway && python3 scripts/key_smoke_test.py [--port /dev/ttyACM0] [--steps reply,panic,autonomy,cancel]

Port and secret default to AIRLOCK_KEY_PORT and AIRLOCK_KEY_SECRET. Sends a real `request` with a made-up
nonce, waits for the tap, and checks the signed reply with keyproto.py. Then waits for a panic press and a
dial change and checks the autonomy signature. Prints PASS or FAIL per step; exit code 0 only if all pass.
The `cancel` step needs your eyes: the key should return to its idle screen.
It does not talk to the gateway. Stop the gateway first (only one program can hold the serial port).
"""
import argparse
import os
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from airlock.keyproto import (SUMMARY_MAX, decode_line, digest, display_text, encode_request,  # noqa: E402
                              verify_parts, verify_reply)

# More than 32 characters, so the LCD build has to page it. 3 pages on the LCD.
SUMMARY = "Smoke test: read every page, then tap approve to confirm the key signs this text"
LEVELS = {"supervised", "balanced", "autonomous"}


def read_msg(ser, timeout: float, want: set[str]) -> dict | None:
    """Next JSON message whose type is in `want`; other lines (boot text, selftest) are printed and skipped."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        raw = ser.readline()
        if not raw:
            continue
        msg = decode_line(raw)
        if msg is None:
            print("  key:", raw.decode("utf-8", "replace").strip())
        elif msg.get("type") in want:
            return msg
    return None


def step_reply(ser, secret: str, wait: float) -> bool:
    action_id, nonce = "smoke" + secrets.token_hex(2), secrets.token_hex(4)
    shown = display_text(SUMMARY)
    print(f"[reply] summary ({len(shown)}/{SUMMARY_MAX} chars): {shown!r}")
    print("[reply] read every page on the key, then press APPROVE (or DENY).")
    ser.write(encode_request(action_id, SUMMARY, nonce, 3).encode())
    msg = read_msg(ser, wait, {"reply"})
    if msg is None:
        print("FAIL reply: no reply before the timeout")
        return False
    if msg.get("action_id") != action_id:
        print("FAIL reply: reply is for a different action_id", msg.get("action_id"))
        return False
    decision = str(msg.get("decision"))
    if decision not in ("approve", "deny"):
        print("FAIL reply: bad decision", decision)
        return False
    if msg.get("digest") != digest(shown):
        print(f"FAIL reply: digest {msg.get('digest')} != {digest(shown)} (key hashed different text)")
        return False
    if not verify_reply(secret, msg.get("hmac"), action_id, decision, nonce, shown):
        print("FAIL reply: HMAC does not verify (wrong secret, or firmware differs from keyproto.py)")
        return False
    print(f"PASS reply: signature valid, decision={decision}")
    return True


def step_panic(ser, wait: float) -> bool:
    print("[panic] press PANIC now: both buttons together.")
    msg = read_msg(ser, wait, {"panic"})
    print("PASS panic: received" if msg else "FAIL panic: nothing received")
    return msg is not None


def step_autonomy(ser, secret: str, wait: float) -> bool:
    print("[autonomy] move the dial to a different zone and leave it there.")
    msg = read_msg(ser, wait, {"autonomy"})
    if msg is None:
        print("FAIL autonomy: nothing received")
        return False
    level, seq = str(msg.get("level")), msg.get("seq")
    if level not in LEVELS or not isinstance(seq, int):
        print("FAIL autonomy: bad level or seq", msg)
        return False
    if not verify_parts(secret, msg.get("hmac"), "autonomy", level, seq):
        print("FAIL autonomy: HMAC does not verify")
        return False
    print(f"PASS autonomy: level={level} seq={seq} signature valid")
    return True


def step_cancel(ser) -> bool:
    action_id = "smoke" + secrets.token_hex(2)
    ser.write(encode_request(action_id, SUMMARY, secrets.token_hex(4), 3).encode())
    print("[cancel] a request is on the key; sending cancel in 3 s. The key should return to idle (READY).")
    time.sleep(3)
    ser.write(('{"type":"cancel","action_id":"%s"}\n' % action_id).encode())
    print("PASS cancel: sent (confirm by eye that the screen went back to idle)")
    return True


def run(ser, secret: str, steps: list[str], wait: float = 70.0) -> bool:
    results = []
    for s in steps:
        if s == "reply":
            results.append(step_reply(ser, secret, wait))
        elif s == "panic":
            results.append(step_panic(ser, wait))
        elif s == "autonomy":
            results.append(step_autonomy(ser, secret, wait))
        elif s == "cancel":
            results.append(step_cancel(ser))
        else:
            print("unknown step", s)
            results.append(False)
    ok = all(results)
    print("PASS" if ok else "FAIL")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=os.getenv("AIRLOCK_KEY_PORT"))
    ap.add_argument("--secret", default=os.getenv("AIRLOCK_KEY_SECRET", "dev-secret-change-me"))
    ap.add_argument("--steps", default="reply,panic,autonomy,cancel")
    ap.add_argument("--wait", type=float, default=70.0, help="seconds to wait for each human action")
    args = ap.parse_args()
    if not args.port:
        sys.exit("set AIRLOCK_KEY_PORT or pass --port")
    import serial  # pyserial

    with serial.Serial(args.port, 115200, timeout=0.2) as ser:
        time.sleep(2.0)  # opening the port resets the Uno; let it boot
        ser.reset_input_buffer()
        sys.exit(0 if run(ser, args.secret, args.steps.split(","), args.wait) else 1)


if __name__ == "__main__":
    main()
