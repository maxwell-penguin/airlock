import asyncio
import json
import queue

import pytest

from airlock.approvals import SerialKeyChannel
from airlock.keyproto import sign_parts, sign_reply
from airlock.models import Action


class FakeSerial:
    def __init__(self):
        self.written: list[str] = []
        self._rx: queue.Queue = queue.Queue()

    def write(self, data: bytes):
        self.written.append(data.decode())

    def readline(self) -> bytes:
        try:
            return self._rx.get(timeout=0.05)
        except queue.Empty:
            return b""

    def feed(self, msg: dict):
        self._rx.put((json.dumps(msg) + "\n").encode())


def make(fake, **kw):
    return SerialKeyChannel("fake", "secret", serial_factory=lambda: fake, **{"settle_s": 0, **kw})


def test_valid_signed_reply_resolves():
    async def main():
        fake = FakeSerial()
        ch = make(fake)
        ch.start(asyncio.get_running_loop())
        action = Action(id="a1", type="send_message", summary="Send message to bob", details={})

        async def human():
            await asyncio.sleep(0.15)
            req = json.loads(fake.written[0])
            mac = sign_reply("secret", "a1", "approve", req["nonce"], req["summary"])
            fake.feed({"type": "reply", "action_id": "a1", "decision": "approve", "hmac": mac})

        asyncio.create_task(human())
        reply = await asyncio.wait_for(ch.request(action, "n0nce01"), 2)
        ch.stop()
        return reply

    reply = asyncio.run(main())
    assert reply.decision == "approve" and reply.channel == "key"


@pytest.mark.parametrize("secret,decision,sign_decision", [
    ("wrong-secret", "approve", "approve"),   # forged key
    ("secret", "approve", "deny"),            # decision flipped after signing
])
def test_forged_reply_is_ignored(secret, decision, sign_decision):
    async def main():
        fake = FakeSerial()
        ch = make(fake)
        ch.start(asyncio.get_running_loop())
        action = Action(id="a1", type="send_message", summary="Send message to bob", details={})

        async def attacker():
            await asyncio.sleep(0.15)
            req = json.loads(fake.written[0])
            mac = sign_reply(secret, "a1", sign_decision, req["nonce"], req["summary"])
            fake.feed({"type": "reply", "action_id": "a1", "decision": decision, "hmac": mac})

        asyncio.create_task(attacker())
        try:
            await asyncio.wait_for(ch.request(action, "n0nce01"), 0.6)
            return "resolved"
        except asyncio.TimeoutError:
            return "ignored"
        finally:
            ch.stop()

    assert asyncio.run(main()) == "ignored"


def test_panic_and_signed_dial_reach_callback_replay_does_not():
    async def main():
        fake, got = FakeSerial(), []
        ch = make(fake, on_message=got.append)
        ch.start(asyncio.get_running_loop())
        fake.feed({"type": "panic"})
        good = {"type": "autonomy", "level": "autonomous", "seq": 1, "hmac": sign_parts("secret", "autonomy", "autonomous", 1)}
        fake.feed(good)
        fake.feed(good)  # replay
        fake.feed({"type": "autonomy", "level": "autonomous", "seq": 2, "hmac": "bad"})  # forged
        await asyncio.sleep(0.4)
        ch.stop()
        return got

    got = asyncio.run(main())
    assert got == [{"type": "panic"}, {"type": "autonomy", "level": "autonomous"}]
