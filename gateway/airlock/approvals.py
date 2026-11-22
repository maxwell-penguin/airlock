"""Approval channels (hardware key, dashboard, mock) and the manager that races them. Layer 3.

Invariants: first valid reply wins, but if replies arrive in the same instant a deny beats an approve; only an explicit
"approve" approves; timeout, no eligible channel, and lost connections all end in DENY; a forged, malformed or mismatched
key reply is ignored (the request then times out to deny) and can never stop the reader thread (the panic button
must keep working); the dashboard cannot approve critical actions when a key is attached (config.py).
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Callable

from pydantic import BaseModel

from .keyports import is_auto, list_serial_ports, moved_port_hint, resolve_key_port
from .keyproto import decode_line, display_text, encode_autonomy_state, encode_request, verify_parts, verify_reply
from .models import Action, Autonomy
from .external import external_view
from .tools import message_view


log = logging.getLogger("airlock.key")
DEFAULT_SETTLE_S = 3.0                            # opening the port resets the Uno; wait for the boot text to finish
MAX_LINE = 65536                                  # a longer serial line is not one of ours
AUTONOMY_LEVELS = {level.value for level in Autonomy}


class ChannelReply(BaseModel):
    decision: str  # approve | deny
    channel: str


class ApprovalChannel:
    name = "base"

    def can_approve(self, action: Action, critical: bool) -> bool:
        return True

    async def request(self, action: Action, nonce: str) -> ChannelReply | None:
        raise NotImplementedError

    def cancel(self, action_id: str) -> None:
        pass

    def show_autonomy(self, level: str) -> None:
        """The autonomy level changed (from any source). Display only: a channel may show it, never act on it."""
        pass

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        pass

    def stop(self) -> None:
        pass


class MockChannel(ApprovalChannel):
    """Answers automatically. For tests, the scoreboard and key-less development."""
    name = "mock"

    def __init__(self, decision: str = "approve", delay: float = 0.0):
        self.decision = decision
        self.delay = delay

    async def request(self, action: Action, nonce: str) -> ChannelReply | None:
        await asyncio.sleep(self.delay)
        return ChannelReply(decision=self.decision, channel=self.name)


class DashboardChannel(ApprovalChannel):
    """Software approve/deny buttons on the dashboard (also the phone fallback)."""
    name = "dashboard"

    def __init__(self, allow_critical: bool = False):
        self.allow_critical = allow_critical
        self._waiting: dict[str, asyncio.Future] = {}

    def can_approve(self, action: Action, critical: bool) -> bool:
        return self.allow_critical or not critical

    async def request(self, action: Action, nonce: str) -> ChannelReply | None:
        fut = asyncio.get_running_loop().create_future()
        self._waiting[action.id] = fut
        try:
            return await fut
        finally:
            self._waiting.pop(action.id, None)

    def resolve(self, action_id: str, decision: str) -> bool:
        fut = self._waiting.get(action_id)
        if fut is None or fut.done():
            return False
        fut.set_result(ChannelReply(decision=decision, channel=self.name))
        return True


def _resolve(fut: asyncio.Future, value: ChannelReply) -> None:
    if not fut.done():
        fut.set_result(value)


class _Pending:
    """A request waiting for the key. `nonce` is the ONLY nonce a reply may carry right now; None means no reply is accepted
    (never sent on this connection, or the link dropped and the old nonce was invalidated)."""
    __slots__ = ("action_id", "summary", "risk", "shown", "fut", "first_nonce", "nonce", "ever_sent", "conn")

    def __init__(self, action: Action, shown: str, fut: asyncio.Future, nonce: str):
        self.action_id, self.summary, self.risk, self.shown, self.fut = action.id, action.summary, action.risk, shown, fut
        self.first_nonce, self.nonce, self.ever_sent, self.conn = nonce, None, False, None


class _Refused(Exception):
    """AIRLOCK_KEY_PORT=auto could not choose (none or several candidates)."""


class SerialKeyChannel(ApprovalChannel):
    """The hardware key (Arduino Uno) over USB serial, as a SUPERVISED link.

    One supervisor thread owns the connection. It opens the port (retrying with backoff, never crashing or blocking startup),
    waits `settle_s` while the board reboots after the open (draining boot text), then reads until anything goes wrong, closes
    the port, marks the key disconnected and reconnects. Nothing a port can do (missing, permission error, unplugged, garbage,
    oversized or ill-typed lines) can stop that thread.

    Approvals fail closed. A request keeps waiting while the key is gone, until the manager's timeout (which is a deny). When
    the link drops, every pending request's nonce is INVALIDATED at once; after a reconnect (and the settle window) a request that
    is still pending is re-sent with the same action_id and a NEW nonce, so a reply to the old request can never be replayed.
    The autonomy level in force (show_autonomy) is re-sent on every connect too, for the key's idle screen.
    UNVERIFIED on real hardware: every test uses a fake serial port.
    """
    name = "key"

    def __init__(self, port: str, secret: str, baud: int = 115200,
                 serial_factory: Callable[[], object] | None = None,
                 on_message: Callable[[dict], None] | None = None, seq_path: Path | None = None, *,
                 settle_s: float = DEFAULT_SETTLE_S, backoff_start: float = 1.0, backoff_max: float = 10.0,
                 on_link: Callable[[bool, dict], None] | None = None, port_lister: Callable[[], list] | None = None):
        self.port, self.secret, self.baud = port, secret, baud
        self._setting = port                       # what was configured: a concrete path, or "auto"
        self._seq_path = Path(seq_path) if seq_path else None
        self._factory = serial_factory
        self._lister = port_lister
        self.on_message = on_message
        self.on_link = on_link
        self._settle_s, self._backoff_start, self._backoff_max = settle_s, backoff_start, backoff_max
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._dead = threading.Event()             # a write failed: the supervisor should drop and reopen the port
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._waiting: dict[str, _Pending] = {}
        self._finished: dict[str, int | None] = {}  # action_id -> the connection it was sent on (None = never sent), for cancel
        self._ser = None
        self._ready = False                         # open, settled and not failing
        self._conn_id = 0
        self._announced = False
        self._warned: str | None = None
        self._last_seen: float | None = None
        self._last_error: str | None = None
        self._autonomy: str | None = None           # the level the key should show; None = never told, send nothing
        self._last_seq = self._load_seq()  # kept across restarts AND reconnects: a recorded autonomy message cannot be replayed

    # --- state ------------------------------------------------------------------------------------------------------------
    @property
    def configured(self) -> bool:
        return True

    @property
    def connected(self) -> bool:
        """Open, settled, and the last read did not fail. A yanked cable turns this off at the next read."""
        return self._ready and self._thread is not None and self._thread.is_alive()

    @property
    def state(self) -> str:
        return "connected" if self.connected else "reconnecting"

    @property
    def last_seen(self) -> float | None:
        """When the link was last known good (advances while connected, freezes when the key is lost); None if never."""
        return self._last_seen

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def _load_seq(self) -> int:
        try:
            return max(0, int(self._seq_path.read_text())) if self._seq_path else 0
        except (OSError, ValueError):
            return 0

    def _save_seq(self) -> None:
        if self._seq_path is None:
            return
        try:
            self._seq_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._seq_path.with_suffix(".tmp")
            tmp.write_text(str(self._last_seq))
            os.replace(tmp, self._seq_path)
        except OSError:
            pass  # the in-memory value still protects this run

    # --- lifecycle --------------------------------------------------------------------------------------------------------
    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Never raises and never waits for the port: the supervisor opens it in the background."""
        self._loop = loop
        self._setting = self.port
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="key-link", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.5)

    # --- the supervisor -----------------------------------------------------------------------------------------------------
    def _run(self) -> None:
        pause = self._backoff_start
        while not self._stop.is_set():
            try:
                served = self._cycle()
            except BaseException:  # a bug here must still not kill the link
                log.exception("approval key link: unexpected error, continuing")
                served = False
            if served:
                pause = self._backoff_start
            if self._stop.wait(pause):
                break
            if not served:
                pause = min(pause * 2, self._backoff_max)

    def _open(self):
        if is_auto(self._setting):
            port, msg = resolve_key_port(self._setting, self._lister)
            if port is None:
                raise _Refused(msg)
            self.port = port
        if self._factory is not None:
            return self._factory()
        import serial  # pyserial, imported lazily so mock mode needs no hardware libs (ImportError is handled like any open error)
        return serial.Serial(self.port, self.baud, timeout=0.2)

    def _cycle(self) -> bool:
        """One connection from open to loss. True if it got as far as being ready."""
        try:
            ser = self._open()
        except BaseException as exc:
            self._note_failure(exc, opening=True)
            return False
        served = False
        try:
            with self._lock:
                self._ser = ser
                self._dead.clear()
            self._pump(ser, self._settle_s)    # the board reboots when the port opens: wait and drain its boot text
            self._go_ready()
            served = True
            self._pump(ser, None)
        except BaseException as exc:
            if not self._stop.is_set():
                self._note_failure(exc)
        finally:
            self._link_down(ser)
        return served

    def _pump(self, ser, seconds: float | None) -> None:
        """Read lines for `seconds` (or until the link fails or we stop). Exceptions from the port end the connection; anything
        wrong with the DATA is ignored, line by line."""
        end = None if seconds is None else time.monotonic() + seconds
        while not self._stop.is_set():
            if end is not None and time.monotonic() >= end:
                return
            if self._dead.is_set():
                raise OSError("write to the key failed")
            raw = ser.readline()
            self._last_seen = time.time()
            if not isinstance(raw, (bytes, bytearray)) or not raw or len(raw) > MAX_LINE:
                continue
            try:  # one bad line (bad JSON, wrong types, deep nesting, ...) must never stop the key: the panic button depends on it
                msg = decode_line(bytes(raw))
                if msg:
                    self._handle(msg)
            except Exception:
                continue

    def _go_ready(self) -> None:
        with self._lock:
            self._conn_id += 1
            self._ready = True
            pending = list(self._waiting.values())
        if self._warned is not None:
            log.info("approval key connected on %s", self.port)
        self._warned = None
        self._announce(True)
        self._push_autonomy()          # the board rebooted when the port opened: tell it the level in force
        for entry in pending:
            self._deliver(entry)       # still pending: sent now (same action_id; a new nonce if it was sent before)

    def _link_down(self, ser) -> None:
        with self._lock:
            was_ready = self._ready
            self._ready = False
            for entry in self._waiting.values():
                entry.nonce, entry.conn = None, None   # no reply to an old request is accepted any more
            self._ser = None
        try:
            ser.close()
        except Exception:
            pass
        if was_ready and not self._stop.is_set():
            log.warning("approval key disconnected from %s; retrying. Critical actions wait for it and are denied on timeout.", self.port)
            self._announce(False)

    def _note_failure(self, exc: BaseException, opening: bool = False) -> None:
        self._last_error = type(exc).__name__
        if isinstance(exc, _Refused):
            msg = str(exc)
        elif isinstance(exc, ImportError):
            msg = "pyserial is not installed (pip install pyserial), so the key cannot be used"
        else:
            msg = f"{type(exc).__name__}: {str(exc)[:160]}"
            hint = self._moved_hint() if opening else ""
            if hint:
                msg = f"{msg}. {hint}"
        if msg != self._warned:
            self._warned = msg
            log.warning("approval key not available: %s. The gateway keeps running and retries in the background; "
                        "critical actions wait for the key and are denied on timeout.", msg)

    def _moved_hint(self) -> str:
        """Where the key may be now, if the configured path vanished (advice only, see keyports.moved_port_hint). Real ports are
        listed only for a real port: a fake serial factory without a fake lister is a test, which must not read this machine's."""
        lister = self._lister or (list_serial_ports if self._factory is None else None)
        if lister is None or is_auto(self._setting):
            return ""
        try:
            return moved_port_hint(self.port, lister())
        except Exception:  # no pyserial, a listing error: no advice, never a crash
            return ""

    def _announce(self, connected: bool) -> None:
        with self._lock:
            if connected == self._announced:
                return
            self._announced = connected
        cb = self.on_link
        if cb:
            try:
                cb(connected, {"port": self.port, "error": None if connected else self._last_error})
            except Exception:
                log.exception("on_link callback failed")

    # --- requests ---------------------------------------------------------------------------------------------------------------
    def _write(self, ser, line: str) -> None:
        with self._write_lock:
            ser.write(line.encode())

    def _deliver(self, entry: _Pending) -> None:
        with self._lock:
            if not self._ready or entry.fut.done() or entry.conn == self._conn_id or self._ser is None:
                return
            nonce = entry.first_nonce if not entry.ever_sent else secrets.token_hex(8)   # a re-send always gets a new nonce
            entry.nonce, entry.ever_sent, entry.conn = nonce, True, self._conn_id
            ser = self._ser
        try:
            self._write(ser, encode_request(entry.action_id, entry.summary, nonce, entry.risk))
        except Exception:
            with self._lock:
                entry.nonce, entry.conn = None, None   # not delivered: the next connection sends it, with another nonce
            self._dead.set()

    async def request(self, action: Action, nonce: str) -> ChannelReply | None:
        """Waits for the key's reply for as long as the caller lets it (the manager's timeout cancels us). If the key is gone the
        request stays pending and is delivered when it comes back; it is never answered "no key" early."""
        fut = asyncio.get_running_loop().create_future()
        entry = _Pending(action, display_text(action.summary), fut, nonce)
        with self._lock:
            self._waiting[action.id] = entry
            ready = self._ready
        if ready:
            self._deliver(entry)
        try:
            return await fut
        finally:
            with self._lock:
                self._waiting.pop(action.id, None)
                self._finished[action.id] = entry.conn
                while len(self._finished) > 64:
                    self._finished.pop(next(iter(self._finished)))

    def cancel(self, action_id: str) -> None:
        """Tell the key to drop a request that was answered elsewhere or timed out, so a stale one is not left on its screen."""
        with self._lock:
            entry = self._waiting.get(action_id)
            conn = entry.conn if entry is not None else self._finished.pop(action_id, None)
            send = self._ready and conn is not None and conn == self._conn_id
            ser = self._ser
        if send and ser is not None:
            try:
                self._write(ser, '{"type":"cancel","action_id":"%s"}\n' % action_id)
            except Exception:
                pass

    def show_autonomy(self, level: str) -> None:
        """Show the level in force on the key's idle screen. Remembered and re-sent after every reconnect. Display only: the key
        never acts on it, so it is unsigned; a write that fails drops the link like any other, and the reconnect re-sends it."""
        if level not in AUTONOMY_LEVELS:
            return
        with self._lock:
            self._autonomy = level
        self._push_autonomy()

    def _push_autonomy(self) -> None:
        with self._write_lock:   # level read under the write lock, so two quick changes can never reach the key out of order
            with self._lock:
                level, ser = self._autonomy, (self._ser if self._ready else None)
            if level is None or ser is None:
                return
            try:
                ser.write(encode_autonomy_state(level).encode())
            except Exception:
                self._dead.set()

    # --- messages from the key --------------------------------------------------------------------------------------------------
    def _handle(self, msg: dict) -> None:
        kind = msg.get("type")
        if kind == "reply":
            action_id, decision, mac = msg.get("action_id"), msg.get("decision"), msg.get("hmac")
            if not (isinstance(action_id, str) and isinstance(decision, str) and isinstance(mac, str)) or decision not in ("approve", "deny"):
                return
            with self._lock:
                entry = self._waiting.get(action_id)
                nonce = entry.nonce if entry is not None else None
            if entry is None or nonce is None:
                return  # unknown request, or one whose nonce was invalidated by a disconnect
            if not verify_reply(self.secret, mac, action_id, decision, nonce, entry.shown):
                return  # forged, replayed (old nonce) or shown-text mismatch: ignore, request keeps waiting
            if self._loop is not None:
                self._loop.call_soon_threadsafe(_resolve, entry.fut, ChannelReply(decision=decision, channel=self.name))
        elif kind == "panic":
            if self.on_message:
                self.on_message({"type": "panic"})
        elif kind == "autonomy":
            level, seq, mac = msg.get("level"), msg.get("seq"), msg.get("hmac")
            if level not in AUTONOMY_LEVELS or type(seq) is not int or not isinstance(mac, str):
                return  # checked before the sequence number is touched, so junk cannot burn it
            if seq <= self._last_seq or not verify_parts(self.secret, mac, "autonomy", level, seq):
                return
            self._last_seq = seq
            self._save_seq()
            if self.on_message:
                self.on_message({"type": "autonomy", "level": level})


class ApprovalManager:
    def __init__(self, channels: list[ApprovalChannel], timeout: float = 60.0):
        self.channels = channels
        self.timeout = timeout
        self.pending: dict[str, dict] = {}
        self.blocked: Callable[[], bool] | None = None   # set by the gateway: true while frozen
        self._aborts: dict[str, asyncio.Future] = {}     # one per waiting request; deny_all() completes them

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        for c in self.channels:
            c.start(loop)

    def deny_all(self) -> None:
        """End every waiting request as a deny (a freeze happened). Safe from any thread."""
        for fut in list(self._aborts.values()):
            try:
                fut.get_loop().call_soon_threadsafe(lambda f=fut: f.done() or f.set_result(None))
            except RuntimeError:
                pass  # that loop is closed (shutdown): its request is gone with it, and freeze() must still finish the rest

    def stop(self) -> None:
        for c in self.channels:
            c.stop()

    def show_autonomy(self, level: str) -> None:
        for c in self.channels:
            try:
                c.show_autonomy(level)
            except Exception:
                log.exception("show_autonomy failed on channel %s", c.name)

    async def request(self, action: Action, critical: bool = False) -> tuple[str, str]:
        """Returns (decision, channel). decision is approve | deny | timeout."""
        eligible = [c for c in self.channels if c.can_approve(action, critical)]
        if not eligible:
            return "deny", "no-eligible-channel"
        nonce = secrets.token_hex(8)
        self.pending[action.id] = {"action_id": action.id, "summary": action.summary,
                                   "risk": action.risk, "critical": critical, "started": time.time(),
                                   "view": message_view(action), "source": action.source,
                                   "external": external_view(action)}
        abort = asyncio.get_running_loop().create_future()
        self._aborts[action.id] = abort
        if self.blocked and self.blocked():  # frozen between the gateway's check and now (freeze() could not see this request yet)
            self._aborts.pop(action.id, None)
            self.pending.pop(action.id, None)
            return "deny", "frozen"
        tasks = [asyncio.create_task(c.request(action, nonce)) for c in eligible]
        winner: ChannelReply | None = None
        try:
            remaining = set(tasks) | {abort}
            deadline = time.monotonic() + self.timeout
            while remaining and winner is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                done, remaining = await asyncio.wait(remaining, timeout=left, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    break
                if abort in done:
                    return "deny", "frozen"  # the finally below cancels the channels and tells the key to clear its screen
                replies = []
                for t in done:
                    try:
                        reply = t.result()
                    except Exception:
                        reply = None
                    if reply is not None:
                        replies.append(reply)
                if replies:  # several answers in the same instant: any deny wins, so a race can never turn into an approve
                    winner = next((r for r in replies if r.decision != "approve"), replies[0])
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for c in eligible:
                c.cancel(action.id)
            self.pending.pop(action.id, None)
            self._aborts.pop(action.id, None)
            abort.cancel()
        if winner is None:
            return "timeout", "-"
        return ("approve" if winner.decision == "approve" else "deny"), winner.channel
