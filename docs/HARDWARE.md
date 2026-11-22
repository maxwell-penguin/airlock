# Hardware layer: the Airlock approval key

The Airlock key is an Arduino Uno with a small screen and two buttons that sits next to your laptop. When the agent wants to do something risky, the key shows what it wants to do, and a human presses approve or deny. The key signs its answer, so nothing on the laptop can fake a "yes".

**Status: partly verified on hardware.** First-hand results from a real-hardware run on 2026-11-21 are in "Hardware test record" just below. `key_smoke_test.py` has not been run (no result is recorded). Not tested first-hand and still UNVERIFIED: paging of a long summary across the LCD, and unplug and replug mid-request. Setup guide: [firmware/README.md](../firmware/README.md).

## Hardware test record

**2026-11-21, about 22:50 to 23:00, run by Max.** Setup: Arduino Uno, LCD, two button modules (green Approve, yellow Deny) and a dial, gateway in mock mode with `AIRLOCK_KEY_PORT` set, firmware env `uno_lcd` flashed from main at commit `cb3de8d`. The gateway was in mock mode.

| Check | Result |
| --- | --- |
| Self-test passes and the LCD shows AIRLOCK READY | PASS |
| Approve on the key for a critical "email the boss" request | PASS: the message landed in the outbox |
| Deny on the key | PASS: timeline "Denied via key" |
| LCD request text readable, with a 60 s countdown | PASS |
| Timeout with no answer | PASS: ends as deny, the LCD returns to READY |
| Turn the dial | PASS: the gateway's autonomy setting changes, shown on the dashboard, in both directions |
| Panic (both buttons together) | PASS: the agent freezes, the banner shows "panic button pressed"; Resume agent restores it |
| Dashboard Approve and Deny while the key is attached, for a critical request | Seen in the UI: both buttons are disabled |
| `uno_lcd_module` env on this board | **FAILED the self-test**: the serial monitor printed `selftest: FAIL (approve,deny)` and the firmware sent a panic message. `uno_lcd` passed on the same board. The cause was not isolated |
| Paging of a long summary across the LCD | **Not tested first-hand: UNVERIFIED.** Joshua reported it passing (second-hand, no details) |
| Unplug and replug mid-request | **Not tested first-hand: UNVERIFIED.** Joshua reported it passing (second-hand, no details) |

Finding, cause not isolated: with an older build flashed before the Uno refactor merged, the LCD showed scrambled characters while a request was displayed. After re-flashing current main it was clear.

An earlier repo record, before this run: a previous build also passed its boot self-test (SHA-256 and all three contract vectors), and parsed a request and cleared it on cancel.

## Why hardware at all

Software approvals are weak in one specific way: the same machine that runs the agent also draws the approval button. A hijacked agent, a clickjacked page or a tired human clicking through can all produce a "yes". The key moves the decision onto a separate device with its own screen and its own buttons.

- **Out-of-band:** the agent can't approve itself. It has no way to press a physical button.
- **What you see is what you sign:** the key hashes the exact text it displayed and signs that hash, so the gateway can check the key showed the text the gateway sent.
- **Always-available panic:** pressing both buttons freezes the agent and rewinds the workspace, even if the dashboard is closed.

Honest limit: the shared secret is compiled into the firmware (`SHARED_SECRET` in `firmware/src/config.h`). This is demo-grade. See "Next version".

## Parts

| Part | Role |
| --- | --- |
| Arduino Uno (R3) | The brain; USB serial to the laptop |
| LCD1602 (HD44780, 16x2, 4-bit parallel, no I2C backpack) | Shows the action text, paged |
| 2 push buttons: bare switches to GND, or 3-pin button modules (VCC, GND, OUT; OUT goes HIGH when pressed) | Approve and deny; both together is panic |
| 10k potentiometer | Autonomy dial |
| 10k potentiometer + 220 ohm resistor | LCD contrast and backlight |
| Breadboard, jumper wires, USB data cable | Wiring, power and serial |

Pins and power notes: [firmware/WIRING.md](../firmware/WIRING.md). Pin numbers live in `firmware/src/config.h`, which is the source of truth.

**Button modules and the `uno_lcd_module` env.** `uno_lcd_module` is `uno_lcd` plus `-DBUTTON_ACTIVE_HIGH=1`: the pins are plain `INPUT`, they idle **LOW** and read HIGH while pressed, and the boot self-test expects that idle level. Bare switches to GND (`INPUT_PULLUP`, idle HIGH, pressed LOW) are the default env, `uno_lcd`. **On the tested hardware (two button modules, green Approve and yellow Deny) `uno_lcd` passed the self-test and `uno_lcd_module` FAILED it (`selftest: FAIL (approve,deny)`, and the firmware sent a panic message).** The cause was not isolated. No hardware on which `uno_lcd_module` passed is recorded, so do not read this env as the verified choice for button modules. Details and caveats: [firmware/WIRING.md](../firmware/WIRING.md).

## What the key does

1. **Boot:** runs a self-test and prints `selftest: ok` (or `selftest: FAIL (<reasons>)`) over serial, then `ram: N bytes never used`. It checks that both buttons read their idle level (HIGH for `uno_lcd`, bare switches with the internal pull-up; LOW for `uno_lcd_module`), the dial reads within the ADC range (0 to 1023), and that the SHA-256, digest and HMAC code reproduce the known and contract test vectors. The HMAC vectors are only checked when the secret is the default one. It cannot detect a missing screen, because RW is tied to GND and the HD44780 is never read back. The LCD then shows `AIRLOCK  READY` and the dial position (`dial balanced`) until the gateway connects and says which level is in force (`mode balanced`, see 13); a failed self-test shows `SELFTEST FAIL` and the reasons instead.
2. **A request arrives:** the text is wrapped at 16 characters per line, 2 lines per page (32 characters), so up to 84 characters is at most 3 pages. For each page the screen shows a header frame for 0.8 s (`PAGE n/N RISK r`, the risk name, and the seconds left), then the text for 2 s. After the last page a footer frame (1.2 s) shows `APPROVE or DENY` and the countdown, then the cycle repeats. The risk number is the one the gateway sent (3 is EXTERNAL).
3. **Approve:** press and release the approve button. **It is ignored until every page's text has been shown for its full 2 s.** Until then the footer says `read all pages`.
4. **Deny:** press and release the deny button. This works at any time while a request is showing, including before every page has been shown.
5. **Buttons act on release**, so a press that turns into "both at once" never sends a reply first.
6. **Signing covers the full text:** the digest and HMAC are computed over the whole summary the gateway sent, never over a page.
7. **Cancel:** when the gateway sends `cancel` for the request on screen (answered on the dashboard, or timed out), the key clears it and returns to idle. A cancel for a different action is ignored.
8. **Timeout:** the key drops an unanswered request after `APPROVAL_TIMEOUT_S` seconds (default 60) and returns to idle, showing a countdown. It sends nothing; the gateway denies on its own timeout. **The device cannot read the gateway's setting:** if you change `AIRLOCK_APPROVAL_TIMEOUT`, build the firmware with the same value (`-DAPPROVAL_TIMEOUT_S=<n>`).
9. **Panic:** pressing both buttons together sends `{"type":"panic"}` the moment both are down, whether or not a request is showing. Neither button then does anything until both are released.
10. **Dial:** the potentiometer has three zones (supervised, balanced, autonomous). A zone change that holds for 300 ms sends a signed `autonomy` message; the wait stops jitter at a zone edge from sending several. Nothing is sent at boot. The sequence number is saved in EEPROM before each message is sent, so it keeps increasing across reboots.
11. A new request replaces the one on screen.
12. **Fails closed:** a request the key cannot show or sign exactly is ignored, so it ends in timeout, which is deny. That covers malformed JSON, an `action_id` outside `[A-Za-z0-9_-]`, and a summary over 84 characters or not printable ASCII.
13. **Mode on the idle screen:** the gateway sends `autonomy_state` whenever the level changes, from the dashboard, the dial or the API, and after every connect. The idle screen's second row then shows `mode <level>`: the level actually in force. A dial turn therefore shows up only once the gateway has accepted it, so a wrong secret leaves the old mode on screen. The dial is a plain knob, so after a dashboard change its pointer may not match the screen; turning it into another zone sets that zone. Display only: the message is unsigned and changes nothing the buttons or dial do. **UNVERIFIED on hardware** (host tests and fake-serial gateway tests only).

## How the key talks to the gateway

USB serial at 115200 baud, one JSON object per line. The authoritative definition is `gateway/airlock/keyproto.py`, with test vectors in [CONTRACTS.md](CONTRACTS.md).

| Direction | Message | Meaning |
| --- | --- | --- |
| Gateway to key | `request`: `action_id`, `summary` (84 ASCII characters at most), `nonce`, `risk` | "Ask the human about this" |
| Gateway to key | `cancel`: `action_id` | Request resolved elsewhere; the key returns to idle |
| Gateway to key | `autonomy_state`: `level` | The level in force, for the idle screen. Display only, not signed |
| Key to gateway | `reply`: `action_id`, `decision` (`approve` or `deny`), `digest`, `hmac` | The human's answer, signed |
| Key to gateway | `panic` | Freeze now. Always accepted and not signed, because freezing is safe |
| Key to gateway | `autonomy`: `level`, `seq`, `hmac` | The dial moved; `seq` must increase |

Signature: HMAC-SHA256 with the shared secret, lowercase hex.

- reply: message `action_id|decision|nonce|digest`
- autonomy: message `autonomy|level|seq`
- digest: first 16 hex characters of the SHA-256 of the exact displayed text

The gateway recomputes the digest from the text it sent (it does not trust the `digest` field) and checks the HMAC. A forged reply, wrong secret, changed decision, or a mismatch with the displayed text is **ignored**, and the request keeps waiting until it times out, which is a denial. The nonce is new for every request. `request` and `cancel` are unsigned.

The serial line also carries the self-test and `ram:` lines. The gateway ignores any line that does not start with `{`.

Opening the serial port resets the Uno, which takes 1 to 2 seconds to boot. The gateway waits about 3 s after each (re)connect before sending, and the smoke test waits two seconds.

## Gateway settings

| Variable | Meaning |
| --- | --- |
| `AIRLOCK_KEY_PORT` | Serial port, e.g. `/dev/cu.usbmodem3101` (macOS), `/dev/ttyACM0` (Linux) or `COM5` (Windows), used exactly as given. `auto` is an explicit opt-in: it picks the single likely key adapter (Arduino, CH340/CH9102 on Uno clones, CP210x, FTDI, Espressif) and refuses, with a message, if there are none or several. `make key-ports` lists the ports. Unset means no key |
| `AIRLOCK_KEY_SECRET` | Must equal `SHARED_SECRET` in `firmware/src/config.h`. Default `dev-secret-change-me` |
| `AIRLOCK_APPROVAL_TIMEOUT` | Seconds before an unanswered request is denied (default 60). Match `APPROVAL_TIMEOUT_S` in the firmware |
| `AIRLOCK_DASHBOARD_CRITICAL` | Override for whether the dashboard can approve critical actions. By default it follows configuration: a key that is configured but unplugged still counts as attached, so unplugging the cable never lets the dashboard approve a critical action (it is denied on timeout). Set `1` only if you accept that |

If `AIRLOCK_KEY_PORT` is set, the gateway needs `pyserial` (in `requirements.txt`) and connects in the background. A missing port or a failed open never stops the gateway: it logs one warning, reports `key_state: reconnecting`, and retries with backoff (1 s doubling to 10 s). With a fixed path that has vanished, the warning also names where a likely key is listed now (macOS renames the port on a replug into another USB socket); the gateway still uses only the configured path. `auto` looks the key up again on every retry, so it follows a renamed port. Unplugging, replugging or rebooting the key is handled by the same loop: after each (re)connect the gateway waits about 3 s for the board's reset and boot text before the first request. A request still pending when the key returns is shown again with the same `action_id` and a new nonce; the old nonce no longer verifies. If the key does not return, the request is denied at its normal timeout. `make preflight` checks the link (PASS/WARN/FAIL; the key stays optional).
**UNVERIFIED on real hardware:** the reconnect and re-send behaviour. Every automated test of this link uses a fake serial port, and unplug and replug mid-request was not tested first-hand (Joshua reported it passing, second-hand, no details). The firmware treats a second request with the same `action_id` like any new request: it replaces the one on screen, restarts the paging and signs with the new nonce. That has not been run on the board; the worst case is a rejected reply and a timeout, which is a deny.

## Trust and threat model

Trusted: the host, the gateway and the key. Untrusted: the sandbox and the agent.

The key defends against: the agent approving its own actions; a reworded summary (the gateway writes the text, not the agent; see the known gap in [ARCHITECTURE.md](ARCHITECTURE.md)); a forged or replayed approval; approving text that has not been shown (every page must have been on screen).

It does not defend against: someone with physical access to the board or its firmware (the secret is in it); a human pressing approve without reading the pages; a compromised host.

## Build, test and flash

All commands run in `firmware/` and need PlatformIO (`pio`). Full setup: [firmware/README.md](../firmware/README.md).

| Command | What it does |
| --- | --- |
| `pio run -e uno_lcd` | Build the firmware |
| `pio run -e uno_lcd -t upload` | Build and flash the Uno. This env passed the self-test on the tested hardware (2026-11-21) |
| `pio run -e uno_lcd_module -t upload` | The same with `-DBUTTON_ACTIVE_HIGH=1` (pins idle LOW, HIGH when pressed). **Failed the self-test on the tested hardware** (2026-11-21, cause not isolated) |
| `pio device monitor -e uno_lcd` | Watch the serial output (`selftest: ok`, `ram: ...`) |
| `pio test -e native` | Host unit tests of `src/keylogic.h` and `src/flatjson.h` |

Files: `src/config.h` (pins, timeout, secret), `src/keylogic.h` (SHA-256 and HMAC, digest, paging, dial, timeout and button rules; no Arduino code), `src/flatjson.h` (in-place parser for the gateway's messages), `src/main.cpp` (LCD, serial, debouncing, EEPROM, self-test).

**What the native test covers, and what it does not.** `pio test -e native` compiles `keylogic.h` and `flatjson.h` on the host: the same code that runs on the Uno. It checks SHA-256 known answers, the three contract vectors (digest, reply HMAC, autonomy HMAC), paging, the approve gate, deny, panic and release rules, button polarity (pressed and idle level for both wirings, and that the button rules do not depend on it), timeout and dial zones, and parsing of the gateway's real request and cancel lines. It does **not** exercise the hardware code in `main.cpp` (LCD, debouncing, ADC, serial, EEPROM); the boot self-test checks the crypto on the board itself.

**Why the Uno firmware looks the way it does.** The Uno has 2 KB of RAM, no C++ standard library and no hardware crypto. So the key has its own small SHA-256/HMAC, fixed-size buffers, and an in-place JSON parser: ArduinoJson was tried first and left only 36 bytes of RAM untouched after one request; the in-place parser leaves 342. The crypto helpers are kept out of line (`noinline`), because inlined together they nearly overflowed the stack.

**Smoke test on the board:** `gateway/scripts/key_smoke_test.py` (stop the gateway first, only one program can hold the port). It opens `AIRLOCK_KEY_PORT`, sends a real `request` with a made-up nonce, waits for you to approve or deny, and verifies the reply digest and HMAC with `keyproto.py`. It then waits for a panic (both buttons) and a dial change and verifies the autonomy signature, then sends a `cancel` for you to check by eye. It prints PASS or FAIL. Not yet run against the board.

## Bring-up checklist

1. Wire the board following [firmware/WIRING.md](../firmware/WIRING.md), and plug it in.
2. `pio run -e uno_lcd -t upload`, then `pio device monitor -e uno_lcd`. Expect `selftest: ok`, a `ram:` line, and `AIRLOCK  READY` on the LCD. Adjust the contrast pot if the screen is blank or all blocks. (Done on 2026-11-21 with `uno_lcd`: the self-test passed and the LCD showed AIRLOCK READY. `uno_lcd_module` failed the self-test on that hardware, so it is not part of this step.)
3. `cd gateway && python3 scripts/key_smoke_test.py --port <port>`. Read all pages, approve, press both buttons, turn the dial. Expect PASS.
4. Reboot the board, turn the dial again, and confirm the new `seq` is higher than before the reboot.
5. Run the gateway with `AIRLOCK_KEY_PORT` set and start the demo. Confirm `approval_decision` shows channel `key` on the timeline. (Done on 2026-11-21, gateway in mock mode: approve and deny on the key, timeline "Denied via key", the approved message in the outbox.)
6. Only after steps 2 to 5 pass on the board, change the status at the top to verified. Steps 3 and 4 have no recorded result, and paging of a long summary and unplug and replug mid-request are UNVERIFIED, so the status stays "partly verified".

## If something is missing

- **No key attached** (`AIRLOCK_KEY_PORT` unset): the dashboard can approve everything, including critical actions.
- **Key attached:** the dashboard can approve only non-critical actions, unless `AIRLOCK_DASHBOARD_CRITICAL` is set. Critical actions then need the key; with no reply they are denied on timeout.
- **The board dies:** the dashboard and the mock approval channel run the demo without the physical key.

## Next version (the PCBWay pitch)

This is what we would fabricate, not what is built today:

- A custom PCB with a microcontroller, USB-C, a larger screen and tactile buttons, so there is no breadboard and no paging.
- A secure element chip (for example a Microchip ATECC608) that holds the secret and does the signing, so the secret never lives in readable firmware.
- A pairing step that creates a unique secret per key and per user, replacing the hard-coded demo secret.
- An enclosure with a tamper-evident seal.

## Uno status

- **Controls:** tap approve, tap deny, both buttons together = panic, and the dial sets autonomy. Approve, deny, panic and the dial were verified first-hand on 2026-11-21 with `uno_lcd` (see "Hardware test record"). `key_smoke_test.py` has not been run. Paging of a long summary and unplug and replug mid-request are UNVERIFIED.
- **Reset on open:** the Uno reboots when the port opens. The gateway waits about 3 s before its first request and re-sends a still-pending one with a new nonce (see Gateway settings); not yet tried on the board.

## Why not a phone?

A phone is useful as a convenience channel (the dashboard on a phone), but a general-purpose device is a weaker trusted display. We keep the key for critical actions.
