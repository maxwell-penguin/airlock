"""Gateway with a SIMULATED approval key (no hardware): for dashboard development and screenshots only.

    cd gateway && SIM_KEY_TAP=approve|deny python scripts/sim_key_server.py     (default: nobody taps -> timeout = deny)
    SIM_KEY_SEQUENCE=approve,deny   answer request 1 with approve, request 2 with deny, request 3 with approve ... (cycles)
    SIM_KEY_DELAY=4 seconds before the simulated tap;  SIM_KEY_UNPLUG_FILE=<path>: while it exists the cable is "unplugged";  AIRLOCK_STATE_DIR / AIRLOCK_MODE=docker / PORT as usual

A fake serial port stands in for the hardware key, so the dashboard sees key_attached=true and cannot approve critical
actions. Nothing here proves anything about the real firmware. Uses mock mode and a temp state dir.
"""
import json
import os
import queue
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn  # noqa: E402

from airlock.approvals import SerialKeyChannel  # noqa: E402
from airlock.build import build_gateway  # noqa: E402
from airlock.config import Settings  # noqa: E402
from airlock.keyproto import sign_reply  # noqa: E402
from airlock.server import create_app  # noqa: E402

SECRET, TAP = "dev-secret-change-me", os.getenv("SIM_KEY_TAP", "")
SEQUENCE = [x.strip() for x in os.getenv("SIM_KEY_SEQUENCE", "").split(",") if x.strip() in ("approve", "deny")]


UNPLUG_FILE = os.getenv("SIM_KEY_UNPLUG_FILE")  # if this file exists the simulated cable is "unplugged" (reads and writes fail, opening fails)


def _unplugged() -> bool:
    return bool(UNPLUG_FILE) and os.path.exists(UNPLUG_FILE)


def open_simulated_port():
    if _unplugged():
        raise OSError(2, "No such file or directory: simulated key unplugged")
    return FakeSerial()


class FakeSerial:
    def __init__(self):
        self.rx: queue.Queue = queue.Queue()
        self.count = 0

    def close(self):
        pass

    def write(self, data: bytes):
        if _unplugged():
            raise OSError(5, "simulated key unplugged")
        req = json.loads(data.decode())
        decision = (SEQUENCE[self.count % len(SEQUENCE)] if SEQUENCE else TAP) if req.get("type") == "request" else ""
        if req.get("type") == "request":
            self.count += 1
        if decision in ("approve", "deny"):
            def tap():
                time.sleep(float(os.getenv("SIM_KEY_DELAY", "4")))
                mac = sign_reply(SECRET, req["action_id"], decision, req["nonce"], req["summary"])
                self.rx.put((json.dumps({"type": "reply", "action_id": req["action_id"], "decision": decision,
                                         "hmac": mac}) + "\n").encode())
            threading.Thread(target=tap, daemon=True).start()

    def readline(self) -> bytes:
        if _unplugged():
            raise OSError(5, "simulated key unplugged")
        try:
            return self.rx.get(timeout=0.1)
        except queue.Empty:
            return b""


if __name__ == "__main__":
    settings = Settings(state_dir=Path(os.getenv("AIRLOCK_STATE_DIR") or tempfile.mkdtemp(prefix="airlock-sim-")),
                        mode=os.getenv("AIRLOCK_MODE", "mock"), dashboard_can_approve_critical=False,
                        approval_timeout=float(os.getenv("AIRLOCK_APPROVAL_TIMEOUT", "30")),
                        tinyfish=(os.getenv("AIRLOCK_TINYFISH") or "").strip().lower())
    key = SerialKeyChannel("sim", SECRET, serial_factory=open_simulated_port, settle_s=float(os.getenv("SIM_KEY_SETTLE", "0.3")))
    gw = build_gateway(settings, extra_channels=[key])
    key.on_message = gw.handle_device_message
    key.on_link = gw.handle_key_link
    print("SIMULATED key attached; tap =", SEQUENCE or TAP or "nobody", "mode =", settings.mode)
    uvicorn.run(create_app(settings, gw), host="127.0.0.1", port=int(os.getenv("PORT", "8000")))
