"""The link between the gateway and the physical key: unplug, replug, reboot, garbage, no key at all.
Every test uses a FAKE serial port (a controllable "cable"), so nothing here has been run against real hardware.
No Docker, no real serial device."""
import asyncio
import json
import logging
import queue
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

from airlock.approvals import ApprovalManager, MockChannel, SerialKeyChannel
from airlock.build import build_gateway
from airlock.config import REPO_DIR, Settings, load_settings
from airlock.keyproto import sign_parts, sign_reply
from airlock.models import Action
from airlock.server import create_app

from .conftest import run

SECRET = "secret"


class FakeSerial:
    """One open connection. `dead` simulates a yanked cable: every call raises, like a real port that disappeared."""

    def __init__(self, boot=()):
        self.rx: queue.Queue = queue.Queue()
        self.written: list[str] = []
        self.dead = False
        self.closed = False
        for b in boot:
            self.rx.put(b)

    def readline(self):
        if self.dead:
            raise OSError(5, "device disconnected")
        try:
            item = self.rx.get(timeout=0.02)
        except queue.Empty:
            return b""
        if isinstance(item, BaseException):
            raise item
        return item

    def write(self, data: bytes):
        if self.dead:
            raise OSError(5, "device disconnected")
        self.written.append(data.decode())

    def close(self):
        self.closed = True

    def feed(self, msg):
        self.rx.put((json.dumps(msg) + "\n").encode())

    def feed_raw(self, data):
        self.rx.put(data)

    def feed_exc(self, exc):
        self.rx.put(exc)

    def lines(self, kind):
        out = []
        for w in list(self.written):
            try:
                m = json.loads(w)
            except ValueError:
                continue
            if m.get("type") == kind:
                out.append(m)
        return out


class Cable:
    """The USB cable and the board on its end. `factory` is what the channel calls to open the port."""

    def __init__(self, present=True, boot=(b"ets Jun  8 2016 00:22:57\n", b"rst:0x1 (POWERON_RESET)\n", b"selftest: ok\n")):
        self.present, self.boot = present, boot
        self.open_error: BaseException | None = None
        self.opens = 0
        self.open_times: list[float] = []
        self.history: list[FakeSerial] = []

    @property
    def current(self) -> FakeSerial | None:
        return self.history[-1] if self.history else None

    def factory(self):
        self.opens += 1
        self.open_times.append(time.monotonic())
        if self.open_error is not None:
            raise self.open_error
        if not self.present:
            raise OSError(2, "No such file or directory: '/dev/fake'")
        ser = FakeSerial(self.boot)
        self.history.append(ser)
        return ser

    def unplug(self):
        self.present = False
        if self.current is not None:
            self.current.dead = True

    def plug(self):
        self.present = True


def make_key(cable, settle_s=0.1, **kw):
    kw.setdefault("backoff_start", 0.03)
    kw.setdefault("backoff_max", 0.12)
    return SerialKeyChannel("fake", SECRET, serial_factory=cable.factory, settle_s=settle_s, **kw)


async def until(pred, timeout=4.0, what="condition"):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def reply_for(req, decision="approve", secret=SECRET):
    return {"type": "reply", "action_id": req["action_id"], "decision": decision,
            "hmac": sign_reply(secret, req["action_id"], decision, req["nonce"], req["summary"])}


def action(aid="a1", summary='Send to bob@x.test: "hi"'):
    return Action(id=aid, type="send_message", summary=summary, risk=3)


def in_loop(coro_fn):
    """Run an async scenario with a started loop; the channel is stopped afterwards."""
    return asyncio.run(coro_fn())


# ===================================================================================================================
# 1. startup without the key
# ===================================================================================================================

def test_start_never_raises_or_blocks_when_the_port_is_missing_and_keeps_retrying():
    cable = Cable(present=False)

    async def scenario():
        ch = make_key(cable)
        t0 = time.monotonic()
        ch.start(asyncio.get_running_loop())
        assert time.monotonic() - t0 < 0.5                                  # startup is not held up
        assert ch.connected is False and ch.state == "reconnecting" and ch.configured is True
        await until(lambda: cable.opens >= 3, what="retries")
        cable.plug()
        await until(lambda: ch.connected, what="connection after the key was plugged in")
        assert ch.state == "connected"
        ch.stop()
    in_loop(scenario)


def test_retries_back_off_instead_of_hammering_the_port():
    cable = Cable(present=False)

    async def scenario():
        ch = make_key(cable, backoff_start=0.05, backoff_max=0.4)
        ch.start(asyncio.get_running_loop())
        await asyncio.sleep(1.2)
        ch.stop()
    in_loop(scenario)
    gaps = [b - a for a, b in zip(cable.open_times, cable.open_times[1:])]
    assert 3 <= cable.opens <= 12, cable.opens
    assert gaps[-1] > gaps[0] * 2 and max(gaps) < 0.9, gaps               # grows, then stops growing


@pytest.mark.parametrize("exc", [PermissionError(13, "Permission denied: '/dev/ttyUSB0'"), OSError(16, "Resource busy"),
                                 RuntimeError("boom"), ValueError("bad"), ImportError("no pyserial")])
def test_any_error_opening_the_port_is_survived_and_retried(exc):
    cable = Cable()
    cable.open_error = exc

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: cable.opens >= 3, what="retries")
        assert ch._thread.is_alive() and not ch.connected
        cable.open_error = None
        await until(lambda: ch.connected, what="connection once the error cleared")
        ch.stop()
    in_loop(scenario)


def test_a_missing_pyserial_is_a_warning_not_a_crash(monkeypatch, caplog):
    monkeypatch.setitem(sys.modules, "serial", None)                      # `import serial` now raises ImportError

    async def scenario():
        ch = SerialKeyChannel("/dev/ttyACM0", SECRET, settle_s=0.05, backoff_start=0.03, backoff_max=0.06)
        with caplog.at_level(logging.WARNING, logger="airlock.key"):
            ch.start(asyncio.get_running_loop())
            await asyncio.sleep(0.4)
        assert ch._thread.is_alive() and ch.connected is False
        ch.stop()
    in_loop(scenario)
    assert any("pyserial" in r.getMessage().lower() for r in caplog.records)


def test_the_warning_is_logged_once_not_on_every_retry(caplog):
    cable = Cable(present=False)

    async def scenario():
        ch = make_key(cable, backoff_start=0.02, backoff_max=0.04)
        with caplog.at_level(logging.WARNING, logger="airlock.key"):
            ch.start(asyncio.get_running_loop())
            await asyncio.sleep(0.6)
        ch.stop()
    in_loop(scenario)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and r.name == "airlock.key"]
    assert cable.opens >= 5 and len(warnings) == 1, (cable.opens, [r.getMessage() for r in warnings])
    assert "/dev/fake" in warnings[0].getMessage() or "fake" in warnings[0].getMessage()


def test_the_gateway_starts_without_the_key_and_reports_it(tmp_path):
    s = Settings(state_dir=tmp_path, approval_timeout=2.0, pages_dir=REPO_DIR / "demo" / "pages", key_port="/dev/airlock-no-such-port")
    gw = build_gateway(s)
    t0 = time.monotonic()
    with TestClient(create_app(s, gw)) as c:
        assert time.monotonic() - t0 < 5
        st = c.get("/state").json()
        assert st["key_configured"] is True and st["key_attached"] is True and st["key_connected"] is False
        assert st["key_state"] == "reconnecting" and st["key_last_seen"] is None
        assert st["dashboard_can_approve_critical"] is False
        assert c.get("/health").json() == {"ok": True}


def test_no_key_configured_reports_not_configured(make_gw):
    st = make_gw().state()
    assert st["key_configured"] is False and st["key_connected"] is False and st["key_state"] == "not_configured" and st["key_last_seen"] is None


# ===================================================================================================================
# 2. a supervised reader that never dies
# ===================================================================================================================

def test_unplug_and_replug_reconnects_and_reports_each_change_once():
    cable = Cable()
    changes = []

    async def scenario():
        ch = make_key(cable, on_link=lambda connected, info: changes.append(connected))
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected, what="first connection")
        first = cable.current
        cable.unplug()
        await until(lambda: not ch.connected, what="disconnect")
        assert ch.state == "reconnecting" and ch._thread.is_alive()
        await until(lambda: cable.opens >= 6, what="failed retries while unplugged")
        assert first.closed is True                                          # the dead port was closed
        cable.plug()
        await until(lambda: ch.connected, what="reconnect")
        assert cable.current is not first
        ch.stop()
    in_loop(scenario)
    assert changes == [True, False, True], changes                            # one event per change, none per failed retry


@pytest.mark.parametrize("exc", [OSError(5, "I/O error"), ValueError("x"), RuntimeError("y"), KeyError("z"), UnicodeDecodeError("utf-8", b"", 0, 1, "bad"),
                                 type("SerialException", (OSError,), {})("device reports readiness to read but returned no data")])
def test_any_exception_from_the_port_triggers_a_reconnect_not_a_dead_thread(exc):
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        cable.current.feed_exc(exc)
        await until(lambda: cable.opens >= 2 and ch.connected, what="a second, working connection")
        assert ch._thread.is_alive()
        ch.stop()
    in_loop(scenario)


GARBAGE = [b"not json\n", b"\n", b"[]\n", b"null\n", b"{" * 80 + b"\n", b"\xff\xfe\x00junk\n", b"\x00" * 200, b"[" * 100000 + b"\n",
           b'{"type":"reply"}\n', b'{"type":"reply","action_id":5,"decision":[],"hmac":{}}\n', b'{"type":"autonomy","level":1,"seq":"x","hmac":null}\n',
           b'{"type":["panic"]}\n', b"A" * 3_000_000 + b"\n", b"ets Jun  8 2016 00:22:57\n", b"rst:0x1 (POWERON_RESET)\n"]
ODD_TYPES = [None, "a string line\n", 12, 3.5, ["x"], bytearray(b"{}\n"), True]


def test_garbage_malformed_oversized_and_oddly_typed_lines_never_kill_the_link():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        t = asyncio.create_task(ch.request(action(), "n0nce01"))
        await until(lambda: cable.current.lines("request"), what="the request on the wire")
        for g in GARBAGE:
            cable.current.feed_raw(g)
        for o in ODD_TYPES:
            cable.current.feed_raw(o)
        await asyncio.sleep(0.5)
        assert ch._thread.is_alive() and ch.connected and cable.opens == 1   # not even a reconnect: bad data is not a link failure
        cable.current.feed(reply_for(cable.current.lines("request")[0]))
        assert (await asyncio.wait_for(t, 3)).decision == "approve"
        ch.stop()
    in_loop(scenario)


def test_slow_responses_do_not_break_the_link():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        t = asyncio.create_task(ch.request(action(), "n0nce01"))
        await until(lambda: cable.current.lines("request"))
        await asyncio.sleep(0.8)                                              # a human taking their time
        assert not t.done() and ch.connected
        cable.current.feed(reply_for(cable.current.lines("request")[0]))
        assert (await asyncio.wait_for(t, 2)).decision == "approve"
        ch.stop()
    in_loop(scenario)


def test_stop_ends_the_supervisor_quickly_even_while_retrying():
    cable = Cable(present=False)

    async def scenario():
        ch = make_key(cable, backoff_start=5.0, backoff_max=5.0)
        ch.start(asyncio.get_running_loop())
        await asyncio.sleep(0.1)
        t0 = time.monotonic()
        ch.stop()
        assert time.monotonic() - t0 < 1.5 and not ch._thread.is_alive()
    in_loop(scenario)


# ===================================================================================================================
# 3. reset settle: opening the port reboots the Uno
# ===================================================================================================================

def test_a_request_during_the_settle_window_waits_and_is_then_sent_once():
    cable = Cable()

    async def scenario():
        ch = make_key(cable, settle_s=0.5)
        ch.start(asyncio.get_running_loop())
        await until(lambda: cable.opens >= 1)
        opened_at = cable.open_times[0]
        t = asyncio.create_task(ch.request(action(), "n0nce01"))              # sent while the board is still rebooting
        await asyncio.sleep(0.2)
        assert cable.current.lines("request") == [] and ch.connected is False and not t.done()
        await until(lambda: cable.current.lines("request"), what="the request after the settle window")
        assert time.monotonic() - opened_at >= 0.45
        assert len(cable.current.lines("request")) == 1
        cable.current.feed(reply_for(cable.current.lines("request")[0]))
        assert (await asyncio.wait_for(t, 2)).decision == "approve"
        ch.stop()
    in_loop(scenario)


def test_boot_text_is_drained_and_never_mistaken_for_a_reply():
    forged = (json.dumps({"type": "reply", "action_id": "a1", "decision": "approve", "hmac": "0" * 64}) + "\n").encode()
    cable = Cable(boot=(b"ets Jun  8 2016\n", forged, b'{"type":"autonomy","level":"autonomous","seq":99,"hmac":"x"}\n', b"selftest: ok\n"))
    levels = []

    async def scenario():
        ch = make_key(cable, settle_s=0.3)
        ch.on_message = levels.append
        t = asyncio.create_task(ch.request(action(), "n0nce01"))
        ch.start(asyncio.get_running_loop())
        await until(lambda: cable.current and cable.current.lines("request"), what="the request after the boot text")
        await asyncio.sleep(0.3)
        assert not t.done()                                                    # the forged boot-time "reply" resolved nothing
        t.cancel()
        ch.stop()
    in_loop(scenario)
    assert levels == []


def test_a_panic_press_in_the_settle_window_is_still_honoured():
    cable = Cable(boot=(b"ets Jun  8 2016\n", b'{"type":"panic"}\n'))
    got = []

    async def scenario():
        ch = make_key(cable, settle_s=0.3)
        ch.on_message = got.append
        ch.start(asyncio.get_running_loop())
        await until(lambda: got, what="panic")
        ch.stop()
    in_loop(scenario)
    assert got == [{"type": "panic"}]                                          # freezing is always safe


# ===================================================================================================================
# 4. disconnect during a pending approval: fail closed, re-send with a NEW nonce
# ===================================================================================================================

def test_while_the_key_is_gone_a_request_keeps_waiting_until_its_normal_timeout_then_denies():
    cable = Cable(present=False)

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        mgr = ApprovalManager([ch], timeout=1.0)
        t0 = time.monotonic()
        res = await mgr.request(action(), True)
        took = time.monotonic() - t0
        ch.stop()
        return res, took
    res, took = in_loop(scenario)
    assert res[0] == "timeout" and 0.9 <= took < 2.0                           # it waited; it did not deny instantly


def test_unplugged_mid_request_still_waits_then_denies():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        mgr = ApprovalManager([ch], timeout=1.2)
        task = asyncio.create_task(mgr.request(action(), True))
        await until(lambda: cable.current.lines("request"))
        t0 = time.monotonic()
        cable.unplug()
        res = await task
        ch.stop()
        return res, time.monotonic() - t0
    res, took = in_loop(scenario)
    assert res[0] == "timeout" and took > 0.5


def test_replug_resends_the_same_action_with_a_new_nonce_and_only_the_new_nonce_approves():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        t = asyncio.create_task(ch.request(action(), "n0nce01"))
        await until(lambda: cable.current.lines("request"))
        first_conn = cable.current
        first = first_conn.lines("request")[0]
        old_reply = reply_for(first)                                           # a perfectly valid reply to the FIRST request
        cable.unplug()
        await until(lambda: not ch.connected)
        cable.plug()
        await until(lambda: ch.connected and cable.current is not first_conn and cable.current.lines("request"), what="the re-sent request")
        second = cable.current.lines("request")[0]
        assert second["action_id"] == first["action_id"] and second["summary"] == first["summary"] and second["risk"] == first["risk"]
        assert second["nonce"] != first["nonce"]
        assert len(cable.current.lines("request")) == 1
        cable.current.feed(old_reply)                                          # replay of the old reply after the reconnect
        await asyncio.sleep(0.3)
        assert not t.done(), "an old-nonce reply must not approve"
        cable.current.feed(reply_for(second))
        assert (await asyncio.wait_for(t, 2)).decision == "approve"
        ch.stop()
    in_loop(scenario)


def test_an_old_reply_arriving_in_the_reconnect_window_is_ignored_even_before_the_resend():
    cable = Cable()

    async def scenario():
        ch = make_key(cable, settle_s=0.5)
        ch.start(asyncio.get_running_loop())
        await until(lambda: cable.opens >= 1 and cable.current)
        await asyncio.sleep(0.6)
        t = asyncio.create_task(ch.request(action(), "n0nce01"))
        await until(lambda: cable.current.lines("request"))
        old = reply_for(cable.current.lines("request")[0])
        cable.unplug()
        await until(lambda: not ch.connected)
        n = len(cable.history)
        cable.plug()
        await until(lambda: len(cable.history) > n, what="the new connection")
        cable.current.feed(old)                                                # lands during the settle window, before the re-send
        await asyncio.sleep(0.2)
        assert not t.done()
        await until(lambda: cable.current.lines("request"), what="the re-send")
        await asyncio.sleep(0.2)
        assert not t.done()
        t.cancel()
        ch.stop()
    in_loop(scenario)


def test_every_reconnect_uses_a_fresh_nonce():
    cable = Cable()
    seen = []

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        t = asyncio.create_task(ch.request(action(), "n0nce01"))
        await until(lambda: cable.current.lines("request"))
        seen.append(cable.current.lines("request")[0]["nonce"])
        for _ in range(3):
            before = len(cable.history)
            cable.unplug()
            await until(lambda: not ch.connected)
            cable.plug()
            await until(lambda: len(cable.history) > before and cable.current.lines("request"), what="a re-sent request")
            seen.append(cable.current.lines("request")[0]["nonce"])
        t.cancel()
        ch.stop()
    in_loop(scenario)
    assert len(seen) == 4 and len(set(seen)) == 4, seen


def test_a_request_that_is_already_answered_or_cancelled_is_not_resent():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        done = asyncio.create_task(ch.request(action("a1"), "n1"))
        gone = asyncio.create_task(ch.request(action("a2"), "n2"))
        await until(lambda: len(cable.current.lines("request")) == 2)
        by_id = {m["action_id"]: m for m in cable.current.lines("request")}
        cable.current.feed(reply_for(by_id["a1"]))
        assert (await asyncio.wait_for(done, 2)).decision == "approve"
        gone.cancel()
        await asyncio.sleep(0.1)
        before = len(cable.history)
        cable.unplug()
        await until(lambda: not ch.connected)
        cable.plug()
        await until(lambda: ch.connected and len(cable.history) > before)
        await asyncio.sleep(0.3)
        assert cable.current.lines("request") == []
        ch.stop()
    in_loop(scenario)


def test_a_request_made_before_the_key_ever_connected_is_delivered_when_it_arrives():
    cable = Cable(present=False)

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        t = asyncio.create_task(ch.request(action(), "n0nce01"))
        await asyncio.sleep(0.2)
        cable.plug()
        await until(lambda: cable.current and cable.current.lines("request"), what="delivery after the key appeared")
        req = cable.current.lines("request")[0]
        assert req["nonce"] == "n0nce01"                                       # first delivery uses the nonce it was given
        cable.current.feed(reply_for(req))
        assert (await asyncio.wait_for(t, 2)).decision == "approve"
        ch.stop()
    in_loop(scenario)


def test_a_write_that_fails_leaves_the_request_pending_for_the_resend():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        cable.current.dead = True                                              # the cable goes between the check and the write
        t = asyncio.create_task(ch.request(action(), "n0nce01"))
        await asyncio.sleep(0.2)
        assert not t.done()
        cable.plug()
        await until(lambda: len(cable.history) >= 2 and cable.current.lines("request"), what="the request on the new connection")
        cable.current.feed(reply_for(cable.current.lines("request")[0]))
        assert (await asyncio.wait_for(t, 2)).decision == "approve"
        ch.stop()
    in_loop(scenario)


def test_the_dashboard_answering_clears_the_request_on_the_key_with_a_cancel():
    """(An existing bug the work uncovered: cancel() looked for a request its own caller had already removed.)"""
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        mgr = ApprovalManager([ch, MockChannel("approve", 0.3)], timeout=3.0)
        res = await mgr.request(action("a77"), False)
        await asyncio.sleep(0.2)
        ch.stop()
        return res
    assert in_loop(scenario)[0] == "approve"
    assert cable.history[0].lines("cancel") == [{"type": "cancel", "action_id": "a77"}]
    assert [w for w in cable.history[0].written if '"cancel"' in w] == ['{"type":"cancel","action_id":"a77"}\n']   # the wire format is unchanged


def test_no_cancel_is_sent_for_a_request_the_key_never_saw():
    cable = Cable(present=False)

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        mgr = ApprovalManager([ch, MockChannel("approve", 0.1)], timeout=2.0)
        await mgr.request(action("a78"), False)
        cable.plug()
        await until(lambda: ch.connected)
        await asyncio.sleep(0.3)
        ch.stop()
    in_loop(scenario)
    assert all(not s.lines("cancel") and not s.lines("request") for s in cable.history)


# ===================================================================================================================
# 5. unplugging must not downgrade the policy
# ===================================================================================================================

def live(tmp_path, **kw):
    s = Settings(state_dir=tmp_path, approval_timeout=1.5, pages_dir=REPO_DIR / "demo" / "pages", key_port="/dev/airlock-no-such-port", **kw)
    return TestClient(create_app(s, build_gateway(s)))


def start_critical(c):
    c.post("/tasks", json={"scenario": "attack_03_html_comment.html"})          # send_message: critical


def test_a_configured_but_unplugged_key_still_blocks_the_dashboard_from_critical_actions(tmp_path):
    with live(tmp_path) as c:
        st = c.get("/state").json()
        assert st["key_attached"] and not st["key_connected"] and st["dashboard_can_approve_critical"] is False
        start_critical(c)
        end = time.time() + 5
        pending = []
        while time.time() < end and not pending:
            pending = c.get("/approvals/pending").json()
            time.sleep(0.05)
        assert pending and pending[0]["critical"] is True
        assert c.post(f"/approvals/{pending[0]['action_id']}", json={"decision": "approve"}).status_code == 409
        end = time.time() + 6
        while time.time() < end and c.get("/approvals/pending").json():
            time.sleep(0.1)
        assert c.get("/outbox").json() == []                                    # nothing was sent: denied on timeout
        decisions = [e["data"] for e in c.get("/events").json() if e["kind"] == "approval_decision"]
        assert decisions and decisions[-1]["decision"] == "timeout"


def test_unplugging_mid_request_does_not_open_the_dashboard(tmp_path):
    cable = Cable()
    s = Settings(state_dir=tmp_path, approval_timeout=1.5, pages_dir=REPO_DIR / "demo" / "pages", dashboard_can_approve_critical=False)
    key = make_key(cable)
    gw = build_gateway(s, extra_channels=[key])
    app = TestClient(create_app(s, gw))
    with app as c:
        end = time.time() + 5
        while time.time() < end and not key.connected:
            time.sleep(0.02)
        assert key.connected
        start_critical(c)
        end = time.time() + 5
        pending = []
        while time.time() < end and not pending:
            pending = c.get("/approvals/pending").json()
            time.sleep(0.05)
        cable.unplug()
        assert c.post(f"/approvals/{pending[0]['action_id']}", json={"decision": "approve"}).status_code == 409
        assert c.get("/state").json()["dashboard_can_approve_critical"] is False


def test_the_explicit_override_still_lets_the_dashboard_approve_and_is_documented(tmp_path, monkeypatch):
    with live(tmp_path, dashboard_can_approve_critical=True) as c:
        assert c.get("/state").json()["dashboard_can_approve_critical"] is True
    monkeypatch.setenv("AIRLOCK_KEY_PORT", "/dev/x")
    monkeypatch.delenv("AIRLOCK_DASHBOARD_CRITICAL", raising=False)
    assert load_settings().dashboard_critical is False                          # a configured key is "attached" whether or not it is plugged in
    monkeypatch.setenv("AIRLOCK_DASHBOARD_CRITICAL", "1")
    assert load_settings().dashboard_critical is True
    monkeypatch.setenv("AIRLOCK_DASHBOARD_CRITICAL", "0")
    assert load_settings().dashboard_critical is False
    monkeypatch.delenv("AIRLOCK_KEY_PORT")
    monkeypatch.delenv("AIRLOCK_DASHBOARD_CRITICAL")
    assert load_settings().dashboard_critical is True                           # no key configured at all


def test_auto_counts_as_a_configured_key_for_policy(monkeypatch):
    monkeypatch.setenv("AIRLOCK_KEY_PORT", "auto")
    monkeypatch.delenv("AIRLOCK_DASHBOARD_CRITICAL", raising=False)
    assert load_settings().key_port == "auto" and load_settings().dashboard_critical is False


# ===================================================================================================================
# 6. state, events, panic and the autonomy sequence across reconnects
# ===================================================================================================================

def test_state_is_live_and_last_seen_freezes_while_the_key_is_gone():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        assert ch.last_seen is None and ch.state == "reconnecting"
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        await asyncio.sleep(0.15)
        a = ch.last_seen
        assert isinstance(a, float) and abs(a - time.time()) < 2 and ch.state == "connected"
        await asyncio.sleep(0.15)
        assert ch.last_seen > a                                                 # advances while the link is healthy
        cable.unplug()
        await until(lambda: not ch.connected)
        gone = ch.last_seen
        await asyncio.sleep(0.3)
        assert ch.last_seen == gone and ch.state == "reconnecting"             # frozen at the moment it was lost
        cable.plug()
        await until(lambda: ch.connected)
        await asyncio.sleep(0.1)
        assert ch.last_seen > gone
        ch.stop()
    in_loop(scenario)


def test_the_gateway_emits_one_event_per_change(tmp_path):
    cable = Cable()
    s = Settings(state_dir=tmp_path, pages_dir=REPO_DIR / "demo" / "pages", dashboard_can_approve_critical=False)
    key = make_key(cable)
    gw = build_gateway(s, extra_channels=[key])
    key.on_link = gw.handle_key_link

    async def scenario():
        gw.bus.attach_loop(asyncio.get_running_loop())
        key.start(asyncio.get_running_loop())
        await until(lambda: key.connected)
        cable.unplug()
        await until(lambda: not key.connected)
        await until(lambda: cable.opens >= 8, what="many failed retries")
        cable.plug()
        await until(lambda: key.connected)
        live_state.update(gw.state())                                            # while it is up (stop() disconnects it)
        key.stop()
    live_state = {}
    asyncio.run(scenario())
    ev = [e for e in gw.audit.list() if e["kind"] in ("key_connected", "key_disconnected")]
    assert [e["kind"] for e in ev] == ["key_connected", "key_disconnected", "key_connected"], [e["kind"] for e in ev]
    assert "error" in ev[1]["data"] and "port" in ev[0]["data"]
    assert live_state["key_connected"] is True and live_state["key_state"] == "connected" and isinstance(live_state["key_last_seen"], float)
    assert live_state["key_configured"] is True


def test_panic_works_before_and_after_a_reconnect(tmp_path):
    cable = Cable()
    s = Settings(state_dir=tmp_path, pages_dir=REPO_DIR / "demo" / "pages", dashboard_can_approve_critical=False)
    key = make_key(cable)
    gw = build_gateway(s, extra_channels=[key])
    key.on_message = gw.handle_device_message

    async def scenario():
        key.start(asyncio.get_running_loop())
        await until(lambda: key.connected)
        cable.current.feed({"type": "panic"})
        await until(lambda: gw.frozen, what="panic before the unplug")
        gw.unfreeze()
        cable.unplug()
        await until(lambda: not key.connected)
        cable.plug()
        await until(lambda: key.connected)
        assert not gw.frozen
        cable.current.feed({"type": "panic"})
        await until(lambda: gw.frozen, what="panic after the reconnect")
        key.stop()
    asyncio.run(scenario())


def test_the_autonomy_sequence_is_not_reset_by_a_reconnect_or_a_key_reboot(tmp_path):
    cable = Cable()
    got = []

    def auto(level, seq):
        return {"type": "autonomy", "level": level, "seq": seq, "hmac": sign_parts(SECRET, "autonomy", level, seq)}

    async def scenario():
        ch = make_key(cable, seq_path=tmp_path / "seq")
        ch.on_message = got.append
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        cable.current.feed(auto("balanced", 5))
        await until(lambda: got)
        for _ in range(2):                                                      # a reconnect, then another (the board rebooted each time)
            before = len(cable.history)
            cable.unplug()
            await until(lambda: not ch.connected)
            cable.plug()
            await until(lambda: ch.connected and len(cable.history) > before)
            cable.current.feed(auto("balanced", 5))                              # the replay
            cable.current.feed(auto("autonomous", 4))                            # an older sequence number
        await asyncio.sleep(0.3)
        assert got == [{"type": "autonomy", "level": "balanced"}]
        cable.current.feed(auto("autonomous", 6))
        await until(lambda: len(got) == 2)
        ch.stop()
    in_loop(scenario)
    assert got[-1] == {"type": "autonomy", "level": "autonomous"}


def test_nothing_in_the_link_code_changes_the_wire_protocol():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        t = asyncio.create_task(ch.request(action("a9", "Open http://demo.local/clean.html"), "9f3c11aa"))
        await until(lambda: cable.current.lines("request"))
        t.cancel()
        ch.stop()
    in_loop(scenario)
    line = cable.history[0].written[0]
    assert line == '{"type":"request","action_id":"a9","summary":"Open http://demo.local/clean.html","nonce":"9f3c11aa","risk":3}\n'


def test_the_default_settle_is_three_seconds_for_boards_that_reset_when_the_port_opens():
    from airlock.approvals import DEFAULT_SETTLE_S
    assert DEFAULT_SETTLE_S == 3.0
    assert SerialKeyChannel("fake", SECRET)._settle_s == 3.0


# ===================================================================================================================
# the key's screen follows the autonomy level (display only)
# ===================================================================================================================

def test_the_level_in_force_is_sent_on_connect_and_again_after_a_reconnect():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.show_autonomy("balanced")                                             # set before the key ever connected
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected and cable.current.lines("autonomy_state"))
        cable.unplug()
        await until(lambda: not ch.connected)
        cable.plug()
        await until(lambda: ch.connected and len(cable.history) == 2 and cable.current.lines("autonomy_state"))
        ch.stop()
    in_loop(scenario)
    for ser in cable.history:                                                    # the board rebooted: told again each time
        assert ser.lines("autonomy_state") == [{"type": "autonomy_state", "level": "balanced"}]


def test_nothing_is_sent_before_a_level_is_known_or_for_an_unknown_level():
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        ch.show_autonomy("yolo")
        ch.show_autonomy("Balanced")
        await asyncio.sleep(0.1)
        ch.stop()
    in_loop(scenario)
    assert cable.history[0].written == []


def test_a_dashboard_change_reaches_the_key_screen(tmp_path):
    """POST /autonomy (the dashboard) -> the key is told; a dial change echoes back the level that was applied."""
    cable = Cable()
    s = Settings(state_dir=tmp_path, pages_dir=REPO_DIR / "demo" / "pages", dashboard_can_approve_critical=False)
    key = make_key(cable)
    gw = build_gateway(s, extra_channels=[key])
    key.on_message = gw.handle_device_message

    async def scenario():
        key.start(asyncio.get_running_loop())
        await until(lambda: key.connected)
        gw.set_autonomy("supervised")
        gw.set_autonomy("autonomous")
        await until(lambda: len(cable.current.lines("autonomy_state")) == 2)
        cable.current.feed({"type": "autonomy", "level": "balanced", "seq": 1, "hmac": sign_parts(SECRET, "autonomy", "balanced", 1)})
        await until(lambda: len(cable.current.lines("autonomy_state")) == 3)
        cable.current.feed({"type": "autonomy", "level": "supervised", "seq": 1, "hmac": "0" * 64})   # forged: not applied, not echoed
        await asyncio.sleep(0.3)
        key.stop()
    asyncio.run(scenario())
    assert [m["level"] for m in cable.history[0].lines("autonomy_state")] == ["supervised", "autonomous", "balanced"]
    assert gw.policy.autonomy.value == "balanced"


def test_the_built_key_starts_at_the_configured_level(tmp_path):
    s = Settings(state_dir=tmp_path, pages_dir=REPO_DIR / "demo" / "pages", autonomy="supervised", key_port="/dev/fake-airlock-key")
    gw = build_gateway(s)                                                        # builds the channel; nothing opens the port
    key = next(c for c in gw.approvals.channels if c.name == "key")
    assert key._autonomy == "supervised"


def test_the_autonomy_state_line_is_not_written_with_a_request_or_changes_the_request_format():
    """A key that is told the level still gets byte-identical request lines (the contract test vectors are untouched)."""
    cable = Cable()

    async def scenario():
        ch = make_key(cable)
        ch.show_autonomy("balanced")
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        t = asyncio.create_task(ch.request(action("a9", "Open http://demo.local/clean.html"), "9f3c11aa"))
        await until(lambda: cable.current.lines("request"))
        t.cancel()
        ch.stop()
    in_loop(scenario)
    assert cable.history[0].written == [
        '{"type":"autonomy_state","level":"balanced"}\n',
        '{"type":"request","action_id":"a9","summary":"Open http://demo.local/clean.html","nonce":"9f3c11aa","risk":3}\n',
    ]
