# Approval key firmware: setup guide

How to build, flash and connect the Airlock approval key: an **Arduino Uno + LCD1602 + potentiometer + two buttons** (approve, deny). For why the key exists and how it behaves, read [docs/HARDWARE.md](../docs/HARDWARE.md). For pins and wiring, read [WIRING.md](WIRING.md).

**Status:** run on real hardware on 2026-11-21 (about 22:50 to 23:00; Arduino Uno, LCD, two button modules (green Approve, yellow Deny) and a dial; gateway in mock mode; env `uno_lcd` flashed from main at commit `cb3de8d`). PASS, first-hand: the self-test and the LCD showing AIRLOCK READY; approve on the key (the message landed in the outbox); deny on the key ("Denied via key"); readable request text with a 60 s countdown; a timeout ending as deny with the LCD back at READY; the dial changing the gateway's autonomy in both directions; panic freezing the agent and Resume agent restoring it. **The `uno_lcd_module` env FAILED the self-test on this board** (`selftest: FAIL (approve,deny)`, and the firmware sent a panic message) while `uno_lcd` passed; the cause was not isolated. **UNVERIFIED:** paging of a long summary across the LCD, and unplug and replug mid-request (Joshua reported both passing, second-hand, no details). The smoke test (step 5) has not been run. The 29 host tests (`pio test -e native`) pass. Full record: [docs/HARDWARE.md](../docs/HARDWARE.md).

## 1. Install PlatformIO

Pick one:

- **VS Code or Cursor:** install the **PlatformIO IDE** extension (opening `firmware/` suggests it). Then open the PlatformIO sidebar (alien-head icon) and use **Project Tasks → uno_lcd → Build / Upload / Monitor**. If Cursor's extension search does not list it, use the terminal option below.
- **Terminal:** `pip install platformio`. If you already have the extension, its CLI is at `~/.platformio/penv/bin/pio`; add that folder to your `PATH` to type plain `pio`.

**Open the `firmware/` folder itself** (File → Open Folder), not the repo root: PlatformIO only finds the project when `platformio.ini` is at the top of the workspace. The first build downloads the AVR toolchain, which takes a minute or two.

## 2. Wire it

Follow [WIRING.md](WIRING.md). Pin numbers come from `src/config.h`. If you wire a pin differently, change it there, not in `main.cpp`.

**Button type:** the default build is `uno_lcd` (bare switches wired to GND). A second build, `uno_lcd_module` (`-DBUTTON_ACTIVE_HIGH=1`: pins idle LOW), exists for 3-pin button modules, but **on the tested hardware (two button modules, green Approve and yellow Deny) `uno_lcd_module` failed the self-test and `uno_lcd` passed** (2026-11-21; cause not isolated). To try the module env anyway, replace `uno_lcd` with `uno_lcd_module` in the commands below and watch for `selftest: FAIL (approve,deny)`. See "Buttons: two options" in [WIRING.md](WIRING.md).

## 3. Find the port

Plug the Uno in with a USB data cable (charge-only cables show no port), then:

```
cd firmware
pio device list
```

The Uno shows up as `/dev/cu.usbmodem…` on macOS (USB ID `2341:0043`), `/dev/ttyACM0` on Linux, or `COM…` on Windows. From the repo root, `make key-ports` lists the ports and marks the likely key. You can also set `AIRLOCK_KEY_PORT=auto` (step 6): the gateway then picks the single likely key itself, and refuses with a message if it finds none or several.

## 4. Build and flash

From `firmware/`:

```
pio run -e uno_lcd                    # build only
pio run -e uno_lcd -t upload          # build and flash (add --upload-port <port> if it picks the wrong one)
pio device monitor -e uno_lcd         # watch the serial output; Ctrl+C to quit
```

On boot the serial output should show:

```
selftest: ok
ram: 342 bytes never used
```

and the LCD should show `AIRLOCK  READY` and the dial position (`dial balanced`). Once the gateway connects, the second row shows the level in force instead (`mode balanced`), and follows changes made on the dashboard. If the screen is blank or shows a row of blocks, turn the contrast pot.

`selftest: FAIL (<reasons>)` names what failed:

| Reason | Meaning |
| --- | --- |
| `approve`, `deny` | that button reads pressed at boot: check its wiring matches your build (switch to GND for `uno_lcd`, module OUT for `uno_lcd_module`) and that it is not held. On the tested hardware `uno_lcd_module` printed `selftest: FAIL (approve,deny)` and the firmware sent a panic message, while `uno_lcd` passed; the cause was not isolated |
| `dial` | the pot reading is out of range |
| `sha`, `digest`, `hmac`, `autohmac` | the crypto does not match the contract vectors: do not use this key |

## 5. Check the key on its own (smoke test)

Close the serial monitor and stop the gateway first: only one program can use the port at a time. Then, from the repo root:

```
make setup                            # once; installs pyserial among others
cd gateway && python3 scripts/key_smoke_test.py --port <port>
```

It sends a real request and asks you to act on the key:

1. **Reply:** read every page, then press approve (or deny). It checks the signature.
2. **Panic:** press **both buttons together**.
3. **Autonomy:** turn the pot into a different zone and leave it there. It checks the signature.
4. **Cancel:** the screen should go back to idle by itself.

It prints PASS or FAIL for each step.

## 6. Connect it to Airlock

From the repo root (macOS or Linux):

```
AIRLOCK_KEY_PORT=auto make server     # gateway on :8000 (or AIRLOCK_KEY_PORT=<port>)
make dashboard                        # in a second terminal; open http://localhost:5173
```

Prefer `auto` if the key may be unplugged while the gateway runs. On macOS the port name depends on the USB socket, so a replug into another socket renames it (`/dev/cu.usbmodem1101` became `/dev/cu.usbmodem101`). A fixed path is used exactly as given, so the gateway keeps retrying the old name and only logs where the key seems to be now; `auto` looks it up again on every retry. `auto` needs the key to be the only likely adapter plugged in.

On Windows (PowerShell), where `make` and `VAR=value command` do not work:

```
pip install -r gateway/requirements-dev.txt
cd gateway; $env:AIRLOCK_KEY_PORT="COM4"; python -m airlock.server
cd dashboard; npm install; npm run dev                # in a second terminal
```

Port 8000 is the API only: opening it in a browser shows `404 Not Found`, which is normal. Use the dashboard.

To confirm the gateway is connected to the key:

```
curl -s http://127.0.0.1:8000/state | grep -o '"key_connected":[a-z]*'    # expect true
```

The gateway connects in the background and keeps retrying, so the key can be plugged in after the gateway starts, or unplugged and replugged. `key_attached` stays true while a key is configured, even if it is unplugged: critical actions then wait for the key and are denied at the timeout.

With the key attached, critical actions (for example `send_message`) can only be approved on the key. The dashboard shows "Approve on the physical key" with its buttons off.

## Settings that must match

The key cannot read the gateway's settings, so these must be set the same on both sides:

| Gateway (environment variable) | Firmware (`src/config.h`) | Default |
| --- | --- | --- |
| `AIRLOCK_KEY_SECRET` | `SHARED_SECRET` | `dev-secret-change-me` (fake, demo only) |
| `AIRLOCK_APPROVAL_TIMEOUT` | `APPROVAL_TIMEOUT_S` (or build with `-DAPPROVAL_TIMEOUT_S=<n>`) | 60 seconds |

A wrong secret does not show an error: the gateway ignores the key's replies, and every request ends in a timeout, which is deny. Never commit a real secret.

## Controls

| Action | How |
| --- | --- |
| Approve | press and release approve (pin 7) |
| Deny | press and release deny (pin 8) |
| Panic (freeze the agent) | press both buttons together |
| Autonomy | turn the pot: supervised, balanced, autonomous |

Approve is ignored until every page of the request has been shown; the last screen says `read all pages` until then, then `APPROVE or DENY`. Deny works at any time.

## Run the firmware tests

```
cd firmware
pio test -e native
```

These run on your computer, with no board, and compile the same `keylogic.h` and `flatjson.h` that run on the Uno. They check SHA-256, the contract vectors, paging, the button rules (approve gate, deny, panic), dial zones, timeout, and parsing of the gateway's real messages. The hardware code in `main.cpp` (LCD, debouncing, serial, EEPROM) is only exercised on the board.

## Files

| File | What it is |
| --- | --- |
| `platformio.ini` | The builds: `uno_lcd` (the key, bare switches; passed on the tested hardware), `uno_lcd_module` (pins idle LOW; failed the self-test on the tested hardware) and `native` (host tests) |
| `src/config.h` | Pins, timeout, shared secret |
| `src/main.cpp` | The hardware side: LCD, serial, debouncing, dial, EEPROM, self-test |
| `src/keylogic.h` | Hardware-independent rules: SHA-256/HMAC, digest, paging, dial, timeout, buttons (host-tested) |
| `src/flatjson.h` | Parser for the gateway's messages (host-tested) |
| `test/` | Host tests: `pio test -e native` |

## Troubleshooting

- **Upload fails, "port busy" or "resource busy":** close the serial monitor, the Arduino IDE, the smoke test or the gateway, whichever has the port.
- **No port shows up:** try another USB cable (charge-only cables carry no data) or another USB port.
- **Nothing happens when the gateway sends a request:** check `key_connected` (step 6). The gateway waits about 3 s after connecting for the Uno to reset and boot; if the key was unplugged, it reconnects by itself within about 10 s and shows the pending request again.
- **Every approval ends in timeout:** the secrets do not match (see above), or the board is on a different port than `AIRLOCK_KEY_PORT`.
- **Scrambled characters on the LCD while a request is shown:** seen once with an older build flashed before the Uno refactor merged; after re-flashing current main it was clear. The cause was not isolated.
- **Approve does nothing:** wait until every page has been shown (`APPROVE or DENY` on the last screen).
- **`ram:` number near 0:** the Uno has 2 KB of RAM. Do not add features to `main.cpp` without making room first.

## Changing the protocol

Do not change the message format, the digest or the HMAC rules in one place only. Any change to `gateway/airlock/keyproto.py` must be made in the firmware and in [docs/CONTRACTS.md](../docs/CONTRACTS.md) at the same time, and the test vectors must keep passing (`make test` and `pio test -e native`). Tell the team first.
