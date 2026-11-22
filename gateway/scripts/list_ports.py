"""List the serial ports and mark the likely key USB-serial adapters.   make key-ports

    cd gateway && python3 scripts/list_ports.py

Shows each port with its USB vendor:product ids (CP210x 10C4, CH340/CH9102 1A86, FTDI 0403, Espressif 303A are marked as likely).
Then either set AIRLOCK_KEY_PORT to the path you want, or opt in to AIRLOCK_KEY_PORT=auto, which picks the single likely
adapter and refuses if there are none or several. A concrete AIRLOCK_KEY_PORT is never second-guessed. Needs pyserial.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from airlock.keyports import dedupe, format_ports, likely_adapter, list_serial_ports  # noqa: E402


def main(argv=None, lister=None) -> int:
    try:
        ports = (lister or list_serial_ports)()
    except ImportError:
        print("pyserial is not installed, so serial ports cannot be listed. Fix: make setup   (or: pip install pyserial)", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"could not list the serial ports ({type(exc).__name__}: {str(exc)[:120]})", file=sys.stderr)
        return 1
    print(format_ports(ports))
    likely = [p for p in dedupe(ports) if likely_adapter(p)]
    print()
    if len(likely) == 1:
        print(f"One likely key: export AIRLOCK_KEY_PORT={likely[0].device}     (or opt in: AIRLOCK_KEY_PORT=auto)")
    elif likely:
        print("Several likely adapters: set AIRLOCK_KEY_PORT to the one that is your key (auto would refuse to guess).")
    else:
        print("No likely key adapter. Plug the key in with a DATA cable (some cables only charge), then run this again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
