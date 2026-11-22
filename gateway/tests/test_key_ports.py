"""Finding the key: port listing, AIRLOCK_KEY_PORT=auto (explicit opt-in only), `make key-ports`, and the preflight key checks.
Fake port lists and a fake serial port: nothing here has touched real hardware."""
import asyncio
import json
import logging
import queue

import pytest

from airlock.keyports import PortInfo, dedupe, format_ports, is_auto, likely_adapter, probe_boot, resolve_key_port

from .test_key_link import Cable, make_key, until

CP210X = PortInfo("/dev/cu.SLAB_USBtoUART", 0x10C4, 0xEA60, "CP2102 USB to UART Bridge Controller", "Silicon Labs", "0001", "20-1")
CH340 = PortInfo("/dev/cu.wchusbserial1410", 0x1A86, 0x7523, "USB Serial", None, None, "20-2")
FTDI = PortInfo("/dev/cu.usbserial-A50285BI", 0x0403, 0x6001, "FT232R USB UART", "FTDI", "A50285BI", "20-3")
UNO_R3 = PortInfo("/dev/cu.usbmodem3101", 0x2341, 0x0043, "IOUSBHostDevice", "Arduino (www.arduino.cc)", "0002", "20-5")
ESP_NATIVE = PortInfo("/dev/cu.usbmodem1101", 0x303A, 0x1001, "USB JTAG/serial debug unit", "Espressif", "AA:BB", "20-4")
BLUETOOTH = PortInfo("/dev/cu.Bluetooth-Incoming-Port", None, None, "n/a")
DEBUG_CONSOLE = PortInfo("/dev/cu.debug-console", None, None, "n/a")
PHONE = PortInfo("/dev/cu.usbmodem9999", 0x05AC, 0x12A8, "iPhone")


# --- recognising adapters --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("port,label", [(UNO_R3, "Arduino"), (CP210X, "CP210x"), (CH340, "CH340"), (FTDI, "FTDI"), (ESP_NATIVE, "Espressif")])
def test_the_usual_usb_serial_adapters_are_recognised(port, label):
    assert label in likely_adapter(port)


@pytest.mark.parametrize("port", [BLUETOOTH, DEBUG_CONSOLE, PHONE, PortInfo("/dev/ttyS0", 0, 0, "x"), PortInfo("COM1", None, None, "Communications Port")])
def test_other_ports_are_not_marked_as_likely(port):
    assert likely_adapter(port) is None


def test_macos_cu_and_tty_entries_for_one_adapter_count_once_and_cu_is_preferred():
    cu = PortInfo("/dev/cu.usbserial-0001", 0x10C4, 0xEA60, "CP2102", None, "0001", "20-1")
    tty = PortInfo("/dev/tty.usbserial-0001", 0x10C4, 0xEA60, "CP2102", None, "0001", "20-1")
    assert dedupe([tty, cu, BLUETOOTH]) == [cu, BLUETOOTH]
    no_serial_number = [PortInfo("/dev/tty.usbserial-14110", 0x1A86, 0x7523, "x"), PortInfo("/dev/cu.usbserial-14110", 0x1A86, 0x7523, "x")]
    assert [p.device for p in dedupe(no_serial_number)] == ["/dev/cu.usbserial-14110"]
    two_boards = [PortInfo("/dev/cu.usbserial-1", 0x10C4, 0xEA60, "x", None, "AAA"), PortInfo("/dev/cu.usbserial-2", 0x10C4, 0xEA60, "x", None, "BBB")]
    assert len(dedupe(two_boards)) == 2                                          # two real boards stay two


def test_the_listing_marks_likely_adapters_with_vendor_and_product_ids():
    text = format_ports([CP210X, BLUETOOTH, PHONE])
    assert "/dev/cu.SLAB_USBtoUART" in text and "10C4:EA60" in text and "likely key USB-serial" in text
    cp_line = next(l for l in text.splitlines() if "SLAB" in l)
    phone_line = next(l for l in text.splitlines() if "9999" in l)
    assert "likely" in cp_line and "likely" not in phone_line and "05AC:12A8" in phone_line
    assert "no serial ports" in format_ports([]).lower()


# --- AIRLOCK_KEY_PORT=auto: explicit opt-in, one candidate, otherwise refuse --------------------------------------------

def boom():
    raise AssertionError("the port list must not even be read for a concrete path")


@pytest.mark.parametrize("value", ["/dev/ttyACM0", "/dev/cu.usbserial-0001", "COM5", "/dev/null", "AUTO-ish", "automatic", "/dev/auto"])
def test_a_concrete_path_is_never_second_guessed(value):
    assert resolve_key_port(value, boom) == (value, "")
    assert is_auto(value) is False


@pytest.mark.parametrize("value", ["auto", "AUTO", " auto ", "Auto"])
def test_auto_is_recognised_when_spelled_out(value):
    assert is_auto(value) is True


def test_auto_picks_the_single_likely_candidate():
    port, msg = resolve_key_port("auto", lambda: [BLUETOOTH, DEBUG_CONSOLE, PHONE, CP210X])
    assert port == CP210X.device and "CP210x" in msg


def test_auto_ignores_the_duplicate_tty_entry_on_macos():
    cu = PortInfo("/dev/cu.usbserial-0001", 0x10C4, 0xEA60, "x", None, "0001")
    tty = PortInfo("/dev/tty.usbserial-0001", 0x10C4, 0xEA60, "x", None, "0001")
    assert resolve_key_port("auto", lambda: [tty, cu])[0] == cu.device


def test_auto_refuses_when_there_are_no_candidates():
    port, msg = resolve_key_port("auto", lambda: [BLUETOOTH, PHONE])
    assert port is None and "no likely" in msg.lower() and "make key-ports" in msg and "AIRLOCK_KEY_PORT" in msg


def test_auto_refuses_when_there_are_several_and_names_them():
    port, msg = resolve_key_port("auto", lambda: [CP210X, CH340, BLUETOOTH])
    assert port is None and CP210X.device in msg and CH340.device in msg and "refus" in msg.lower() and "AIRLOCK_KEY_PORT" in msg


def test_auto_without_pyserial_or_with_a_failing_lister_refuses_cleanly():
    def no_serial():
        raise ImportError("serial")

    def broken():
        raise RuntimeError("tcgetattr")
    p1, m1 = resolve_key_port("auto", no_serial)
    p2, m2 = resolve_key_port("auto", broken)
    assert p1 is None and "pyserial" in m1 and p2 is None and "RuntimeError" in m2


def test_the_channel_with_auto_refuses_to_open_anything_when_ambiguous_then_connects_when_it_is_unambiguous(caplog):
    cable = Cable()
    ports = {"now": [CP210X, CH340]}

    async def scenario():
        ch = make_key(cable, backoff_start=0.03, backoff_max=0.06, port_lister=lambda: list(ports["now"]))
        ch.port = "auto"
        with caplog.at_level(logging.WARNING, logger="airlock.key"):
            ch.start(asyncio.get_running_loop())
            await asyncio.sleep(0.4)
            assert cable.opens == 0 and not ch.connected                         # it never guessed
            ports["now"] = [CP210X]                                              # one board is unplugged
            await until(lambda: ch.connected, what="connection once only one candidate was left")
            assert ch.port == CP210X.device and cable.opens == 1
        ch.stop()
    asyncio.run(scenario())
    msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(msgs) == 1 and "refus" in msgs[0].lower()                          # one clear message, not one per retry


def test_a_concrete_port_is_used_as_is_by_the_channel_and_the_port_list_is_not_read():
    cable = Cable()

    async def scenario():
        ch = make_key(cable, port_lister=boom)
        ch.port = "/dev/ttyACM0"
        ch.start(asyncio.get_running_loop())
        await until(lambda: ch.connected)
        assert ch.port == "/dev/ttyACM0"
        ch.stop()
    asyncio.run(scenario())


# --- the make key-ports script ------------------------------------------------------------------------------------------

def test_list_ports_script_prints_the_listing_and_a_hint(capsys):
    from scripts import list_ports
    rc = list_ports.main([], lister=lambda: [CP210X, BLUETOOTH])
    out = capsys.readouterr().out
    assert rc == 0 and "likely key USB-serial" in out and "AIRLOCK_KEY_PORT=" in out and "10C4:EA60" in out


def test_list_ports_script_explains_a_missing_pyserial_without_a_traceback(capsys):
    from scripts import list_ports

    def no_serial():
        raise ImportError("serial")
    rc = list_ports.main([], lister=no_serial)
    out = capsys.readouterr()
    assert rc == 1 and "pyserial" in (out.out + out.err) and "Traceback" not in (out.out + out.err)


# --- preflight: PASS / WARN / FAIL for the key link, never mandatory -------------------------------------------------------

class BootSerial:
    def __init__(self, lines):
        self.rx = queue.Queue()
        for l in lines:
            self.rx.put(l)
        self.closed = False

    def readline(self):
        try:
            return self.rx.get(timeout=0.01)
        except queue.Empty:
            return b""

    def write(self, data):
        pass

    def close(self):
        self.closed = True


@pytest.fixture
def preflight():
    from scripts import preflight as p
    return p


def test_probe_boot_reads_the_selftest_line():
    ok = probe_boot(BootSerial([b"ets Jun 8\n", b"selftest: ok\n"]), 0.1)
    assert ok["selftest"] == "ok" and len(ok["lines"]) == 2
    bad = probe_boot(BootSerial([b"selftest: FAIL (display,dial)\n"]), 0.1)
    assert bad["selftest"] == "fail" and bad["why"] == "display,dial"
    none = probe_boot(BootSerial([b"garbage \xff\xfe\n", b""]), 0.1)
    assert none["selftest"] is None


def test_no_key_configured_is_a_skip_not_a_failure(preflight, monkeypatch):
    monkeypatch.delenv("AIRLOCK_KEY_PORT", raising=False)
    status, msg, fix = preflight.c_key("mock", smoke=False)
    assert status == "SKIP" and "optional" in msg.lower()


def test_a_configured_key_that_is_not_plugged_in_warns_and_explains_what_happens(preflight, monkeypatch, tmp_path):
    monkeypatch.setenv("AIRLOCK_KEY_PORT", str(tmp_path / "ttyNOPE"))
    status, msg, fix = preflight.c_key("mock", smoke=False)
    assert status == "WARN" and "not found" in msg and "retry" in msg.lower() and "denied" in msg.lower()
    assert "make key-ports" in fix and "unset AIRLOCK_KEY_PORT" in fix


def test_a_key_that_prints_selftest_ok_passes(preflight, monkeypatch, tmp_path):
    port = tmp_path / "ttyOK"
    port.write_text("")
    monkeypatch.setenv("AIRLOCK_KEY_PORT", str(port))
    ser = BootSerial([b"ets Jun  8 2016\n", b"selftest: ok\n"])
    status, msg, fix = preflight.c_key("mock", smoke=False, serial_factory=lambda: ser, settle_s=0.2)
    assert status == "PASS" and "selftest: ok" in msg and "smoke test skipped" in msg and ser.closed


def test_a_key_that_reports_a_failed_selftest_fails_with_the_reason(preflight, monkeypatch, tmp_path):
    port = tmp_path / "ttyBAD"
    port.write_text("")
    monkeypatch.setenv("AIRLOCK_KEY_PORT", str(port))
    status, msg, fix = preflight.c_key("mock", smoke=False, serial_factory=lambda: BootSerial([b"selftest: FAIL (approve,panic)\n"]), settle_s=0.2)
    assert status == "FAIL" and "approve,panic" in msg and "HARDWARE.md" in fix


def test_a_key_that_prints_nothing_warns_and_points_at_the_smoke_test(preflight, monkeypatch, tmp_path):
    port = tmp_path / "ttyQUIET"
    port.write_text("")
    monkeypatch.setenv("AIRLOCK_KEY_PORT", str(port))
    status, msg, fix = preflight.c_key("mock", smoke=False, serial_factory=lambda: BootSerial([]), settle_s=0.2)
    assert status == "WARN" and "key_smoke_test" in fix


@pytest.mark.parametrize("exc", [PermissionError(13, "denied"), OSError(16, "busy")])
def test_a_port_that_exists_but_cannot_be_opened_fails_with_a_fix(preflight, monkeypatch, tmp_path, exc):
    port = tmp_path / "ttyBUSY"
    port.write_text("")
    monkeypatch.setenv("AIRLOCK_KEY_PORT", str(port))

    def refuse():
        raise exc
    status, msg, fix = preflight.c_key("mock", smoke=False, serial_factory=refuse, settle_s=0.1)
    assert status == "FAIL" and type(exc).__name__ in msg and "another program" in fix


def test_auto_in_preflight_warns_when_ambiguous_and_names_the_next_step(preflight, monkeypatch):
    monkeypatch.setenv("AIRLOCK_KEY_PORT", "auto")
    status, msg, fix = preflight.c_key("mock", smoke=False, lister=lambda: [CP210X, CH340])
    assert status == "WARN" and "refus" in msg.lower() and "make key-ports" in fix


def test_auto_in_preflight_probes_the_single_candidate(preflight, monkeypatch, tmp_path):
    monkeypatch.setenv("AIRLOCK_KEY_PORT", "auto")
    ser = BootSerial([b"selftest: ok\n"])
    status, msg, fix = preflight.c_key("mock", smoke=False, lister=lambda: [CP210X], serial_factory=lambda: ser, settle_s=0.2)
    assert status == "PASS" and CP210X.device in msg


def test_preflight_never_prints_the_secret(preflight, monkeypatch, tmp_path):
    port = tmp_path / "ttyS"
    port.write_text("")
    monkeypatch.setenv("AIRLOCK_KEY_PORT", str(port))
    monkeypatch.setenv("AIRLOCK_KEY_SECRET", "super-secret-value-123")
    for ser in (BootSerial([b"selftest: ok\n"]), BootSerial([])):
        status, msg, fix = preflight.c_key("mock", smoke=False, serial_factory=lambda s=ser: s, settle_s=0.1)
        assert "super-secret-value-123" not in msg + fix


def test_the_key_check_is_in_the_preflight_list_and_never_blocks_by_itself(preflight, monkeypatch):
    monkeypatch.delenv("AIRLOCK_KEY_PORT", raising=False)
    names = [n for n, _, _ in preflight.CHECKS]
    assert "key" in names
    status, *_ = preflight.c_key("docker", smoke=False)
    assert status in ("SKIP", "PASS", "WARN")                                     # with no key configured it can only be SKIP


# --- the Arduino Uno -------------------------------------------------------------------------------------------------

UNO = PortInfo("/dev/cu.usbmodem1101", 0x2341, 0x0043, "Arduino Uno", "Arduino (www.arduino.cc)", "85735313", "20-5")
UNO_R3_OLD_PID = PortInfo("/dev/cu.usbmodem1411", 0x2341, 0x0001, "Arduino Uno", "Arduino", "75833", "20-6")
UNO_CLONE = PortInfo("/dev/cu.wchusbserial1420", 0x1A86, 0x7523, "USB Serial", None, None, "20-7")


@pytest.mark.parametrize("port,label", [(UNO, "Arduino"), (UNO_R3_OLD_PID, "Arduino"), (UNO_CLONE, "CH340")])
def test_arduino_uno_adapters_are_recognised(port, label):
    assert label in likely_adapter(port)


def test_the_listing_marks_an_uno():
    out = format_ports([UNO, BLUETOOTH])
    assert "2341:0043" in out and "likely" in out.splitlines()[0]


def test_auto_picks_a_single_uno_and_the_esp32_adapters_still_work():
    assert resolve_key_port("auto", lambda: [UNO, BLUETOOTH, PHONE])[0] == UNO.device
    assert resolve_key_port("auto", lambda: [UNO_CLONE])[0] == UNO_CLONE.device
    assert resolve_key_port("auto", lambda: [CP210X, BLUETOOTH])[0] == CP210X.device
    assert resolve_key_port("auto", lambda: [ESP_NATIVE])[0] == ESP_NATIVE.device


def test_auto_refuses_when_an_uno_and_an_esp32_adapter_are_both_plugged_in():
    port, why = resolve_key_port("auto", lambda: [UNO, CP210X])
    assert port is None and "Refusing to guess" in why and UNO.device in why and CP210X.device in why


def test_a_concrete_path_is_still_never_second_guessed_with_an_uno_attached():
    assert resolve_key_port("/dev/cu.mine", lambda: [UNO]) == ("/dev/cu.mine", "")


# ===================================================================================================================
# a fixed AIRLOCK_KEY_PORT that vanished: advice only (macOS renames the port on a replug into another socket)
# ===================================================================================================================
from airlock.approvals import SerialKeyChannel  # noqa: E402
from airlock.keyports import moved_port_hint  # noqa: E402

UNO_MOVED = PortInfo("/dev/cu.usbmodem101", 0x2341, 0x0043, "IOUSBHostDevice", "Arduino (www.arduino.cc)", "0002", "0-1")


def test_moved_port_hint_points_at_the_single_likely_key():
    hint = moved_port_hint("/dev/cu.usbmodem1101", [BLUETOOTH, DEBUG_CONSOLE, UNO_MOVED])
    assert "/dev/cu.usbmodem101" in hint and "AIRLOCK_KEY_PORT=auto" in hint


def test_moved_port_hint_lists_several_and_says_nothing_when_there_is_nothing_to_say():
    several = moved_port_hint("/dev/cu.usbmodem1101", [UNO_MOVED, CH340])
    assert "/dev/cu.usbmodem101" in several and "/dev/cu.wchusbserial1410" in several and "auto" not in several
    assert moved_port_hint("/dev/cu.usbmodem1101", [BLUETOOTH, DEBUG_CONSOLE]) == ""          # no key plugged in at all
    assert moved_port_hint("/dev/cu.usbmodem3101", [UNO_R3]) == ""                            # the path is still there
    assert moved_port_hint("auto", [UNO_MOVED]) == ""                                         # auto re-resolves by itself


def test_a_vanished_fixed_port_logs_where_the_key_went_but_never_switches_to_it(caplog):
    opened = []

    def factory():
        opened.append(1)
        raise FileNotFoundError(2, "No such file or directory: '/dev/cu.usbmodem1101'")

    async def scenario():
        ch = SerialKeyChannel("/dev/cu.usbmodem1101", "secret", serial_factory=factory, port_lister=lambda: [BLUETOOTH, UNO_MOVED],
                              settle_s=0.05, backoff_start=0.02, backoff_max=0.05)
        ch.start(asyncio.get_running_loop())
        await until(lambda: len(opened) >= 4, what="several retries")
        ch.stop()
        return ch
    with caplog.at_level(logging.WARNING, logger="airlock.key"):
        ch = asyncio.run(scenario())
    warnings = [r.getMessage() for r in caplog.records if "not available" in r.getMessage()]
    assert len(warnings) == 1, warnings                                                        # once, not on every retry
    assert "/dev/cu.usbmodem101" in warnings[0] and "AIRLOCK_KEY_PORT=auto" in warnings[0]
    assert ch.port == "/dev/cu.usbmodem1101" and not ch.connected                              # advice only: never second-guessed


def test_a_test_double_serial_port_never_reads_this_machines_real_ports(monkeypatch):
    import airlock.approvals as ap

    def boom():
        raise AssertionError("listed the real serial ports")
    monkeypatch.setattr(ap, "list_serial_ports", boom)
    ch = SerialKeyChannel("/dev/cu.gone", "secret", serial_factory=lambda: None)
    assert ch._moved_hint() == ""
