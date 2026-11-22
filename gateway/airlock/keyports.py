"""Finding the approval key's serial port. Layer 3 helpers; no Arduino, no protocol: nothing here touches keyproto.py.

AIRLOCK_KEY_PORT is either a concrete path (used exactly as given, never second-guessed) or the explicit opt-in `auto`, which
picks the single likely key USB-serial adapter and REFUSES (with a message saying what to do) if there are none or several.
Likely = a USB vendor id of the key's board (an Arduino Uno: Arduino's own USB, or a CH340 on clones) or another common
USB-serial adapter: CP210x (Silicon Labs), CH340/CH9102 (WCH), FTDI, Espressif's own USB.
Port lists come from pyserial, imported lazily and injectable, so tests use fake lists and nothing needs a device.
UNVERIFIED against real hardware: every test uses fake port lists and a fake serial port.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable

LIKELY_VENDORS = {0x2341: "Arduino", 0x2A03: "Arduino (arduino.org)", 0x10C4: "CP210x (Silicon Labs)", 0x1A86: "CH340/CH9102 (WCH)", 0x0403: "FTDI", 0x303A: "Espressif USB"}


@dataclass(frozen=True)
class PortInfo:
    device: str
    vid: int | None = None
    pid: int | None = None
    description: str = ""
    manufacturer: str | None = None
    serial_number: str | None = None
    location: str | None = None


def likely_adapter(p: PortInfo) -> str | None:
    """The adapter family if this looks like the key's USB-serial adapter, else None."""
    return LIKELY_VENDORS.get(p.vid) if p.vid else None


def is_auto(value: str | None) -> bool:
    return isinstance(value, str) and value.strip().lower() == "auto"


def list_serial_ports() -> list[PortInfo]:
    """Needs pyserial (raises ImportError without it)."""
    from serial.tools import list_ports  # lazy: mock mode and the tests need no serial library
    return [PortInfo(p.device, p.vid, p.pid, p.description or "", p.manufacturer, p.serial_number, p.location) for p in list_ports.comports()]


def _group_key(p: PortInfo) -> tuple:
    stem = re.sub(r"^/dev/(?:cu|tty)\.", "", p.device)  # macOS lists every adapter twice: cu.NAME and tty.NAME
    return (p.vid, p.pid, p.serial_number or p.location or stem)


def dedupe(ports: list[PortInfo]) -> list[PortInfo]:
    """One entry per physical adapter; on macOS the /dev/cu.* entry (the one to open) wins over /dev/tty.*."""
    best: dict[tuple, PortInfo] = {}
    order: list[tuple] = []
    for p in ports:
        k = _group_key(p) if p.vid else ("novid", p.device)
        if k not in best:
            best[k] = p
            order.append(k)
        elif "/cu." in p.device and "/cu." not in best[k].device:
            best[k] = p
    return [best[k] for k in order]


def format_ports(ports: list[PortInfo]) -> str:
    if not ports:
        return "no serial ports found (is the key plugged in? try another cable: some are charge-only)"
    rows = []
    for p in dedupe(ports):
        ids = f"{p.vid:04X}:{p.pid:04X}" if p.vid is not None and p.pid is not None else "----:----"
        fam = likely_adapter(p)
        rows.append(f"  {p.device:<34} {ids}  {(p.description or '')[:34]:<34}" + (f"  <- likely key USB-serial: {fam}" if fam else ""))
    return "\n".join(rows)


def resolve_key_port(value: str, lister: Callable[[], list[PortInfo]] | None = None) -> tuple[str | None, str]:
    """(port, message). A concrete path is returned unchanged and the port list is not even read. Only the explicit value `auto`
    ever chooses: exactly one likely adapter, otherwise (None, why)."""
    if not is_auto(value):
        return value, ""
    try:
        ports = (lister or list_serial_ports)()
    except ImportError:
        return None, "AIRLOCK_KEY_PORT=auto needs pyserial (pip install pyserial); it cannot list serial ports without it"
    except Exception as exc:
        return None, f"AIRLOCK_KEY_PORT=auto could not list the serial ports ({type(exc).__name__})"
    found = [p for p in dedupe(ports) if likely_adapter(p)]
    if len(found) == 1:
        return found[0].device, f"auto: using {found[0].device} ({likely_adapter(found[0])})"
    if not found:
        return None, "AIRLOCK_KEY_PORT=auto found no likely key USB-serial adapter. Run `make key-ports`, then set AIRLOCK_KEY_PORT to the right path."
    names = ", ".join(p.device for p in found)
    return None, f"AIRLOCK_KEY_PORT=auto found {len(found)} likely adapters ({names}). Refusing to guess: set AIRLOCK_KEY_PORT to one of them."


def moved_port_hint(configured: str, ports: list[PortInfo]) -> str:
    """Advice when a concrete AIRLOCK_KEY_PORT has gone missing but a likely key is listed elsewhere. macOS renames the port when
    the board comes back on another USB socket or hub (/dev/cu.usbmodem1101 -> /dev/cu.usbmodem101). Advice ONLY: the configured
    path is still the only one used. '' when there is nothing useful to say."""
    if is_auto(configured) or any(p.device == configured for p in ports):
        return ""
    found = [p for p in dedupe(ports) if likely_adapter(p)]
    if len(found) == 1:
        return (f"{configured} is not listed, but a likely key is at {found[0].device} (a replug into another USB socket "
                f"renames the port). Restart the gateway with AIRLOCK_KEY_PORT=auto, or with that path")
    if found:
        return (f"{configured} is not listed; likely keys are at {', '.join(p.device for p in found)}. "
                f"Set AIRLOCK_KEY_PORT to the right one and restart the gateway")
    return ""


def probe_boot(ser, seconds: float, clock: Callable[[], float] = time.monotonic) -> dict:
    """Read an open port for a while and report the boot text: the firmware prints `selftest: ok` or `selftest: FAIL (<reasons>)`
    after the board resets (opening the port resets the Uno)."""
    lines: list[str] = []
    selftest, why = None, ""
    end = clock() + seconds
    while clock() < end:
        raw = ser.readline()
        if not raw or not isinstance(raw, (bytes, bytearray)):
            continue
        text = bytes(raw).decode("utf-8", "replace").strip()
        if not text:
            continue
        lines.append(text)
        m = re.match(r"selftest:\s*(ok|FAIL)(?:\s*\((.*)\))?", text)
        if m:
            selftest, why = ("ok" if m.group(1) == "ok" else "fail"), (m.group(2) or "")
    return {"lines": lines, "selftest": selftest, "why": why}
