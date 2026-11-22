# Wiring: Arduino Uno + LCD1602

`src/config.h` is the source of truth for pins; this file explains them. How to flash, test and connect the key: [README.md](README.md).

## Pins

| Function | Uno pin | Notes |
| --- | --- | --- |
| LCD RS | 12 | |
| LCD E | 11 | |
| LCD D4 | 5 | |
| LCD D5 | 4 | |
| LCD D6 | 3 | |
| LCD D7 | 2 | |
| Approve button | 7 | see "Buttons: two options" |
| Deny button | 8 | see "Buttons: two options" |
| Autonomy dial (pot wiper) | A2 | pot ends on 5V and GND |

Panic is both buttons pressed together, so no third button is needed. LCD data lines D0-D3 stay unconnected (4-bit mode).

## Buttons: two options

Pins 7 (approve) and 8 (deny) work with either kind of button. Pick the option that matches your hardware and build the matching env. Do not mix the two kinds on one board.

### Option A: bare switches to GND (env `uno_lcd`, the default)

One leg of each switch to the pin, the other leg to GND. The firmware turns on the Uno's internal pull-up (`INPUT_PULLUP`): the pin idles **HIGH** and a press pulls it **LOW**. No resistors needed.

### Option B: button modules with OUT (env `uno_lcd_module`)

**Not verified on hardware, and it failed once.** On the tested hardware (two button modules, green Approve and yellow Deny; 2026-11-21) the `uno_lcd_module` env FAILED the boot self-test (`selftest: FAIL (approve,deny)`, and the firmware sent a panic message) while `uno_lcd` passed. The cause was not isolated. This section describes what the env expects, not a recipe known to work.

The env expects 3-pin button boards (VCC, GND, OUT) that carry their own pull-down and drive OUT **HIGH when pressed**:

| Module pin | Connect to |
| --- | --- |
| VCC | 5V on the Uno |
| GND | GND |
| OUT (approve module) | pin 7 |
| OUT (deny module) | pin 8 |

The firmware sets these pins to plain `INPUT` (the module supplies the pull-down; the internal pull-up would fight it). The pin idles **LOW** and reads **HIGH** only while the button is held. The boot self-test expects LOW at idle for this build, and HIGH at idle for option A.

- If a module is not connected, a plain `INPUT` pin floats and may read either level, so the boot self-test cannot reliably tell "missing" from "idle" in this build. Check the wiring before trusting `selftest: ok`.
- A module whose OUT is **active LOW** (pulls to GND when pressed) is the opposite polarity: use option A's build for it.
- Approve, deny and panic (both together) behave the same for both options.

```
pio run -e uno_lcd_module -t upload      # button modules (option B)
pio run -e uno_lcd -t upload             # bare switches (option A)
```

`uno_lcd_module` is not in `default_envs`; name it explicitly. It builds `uno_lcd` plus `-DBUTTON_ACTIVE_HIGH=1`. It failed the self-test on the tested hardware (see the note above); no hardware on which it passed is recorded.

## LCD1602 pins (HD44780, no I2C backpack, 16-pin header)

| LCD pin | Name | Connect to |
| --- | --- | --- |
| 1 | VSS | GND |
| 2 | VDD | 5V |
| 3 | V0 (contrast) | wiper of the contrast pot (its two ends go to 5V and GND) |
| 4 | RS | Uno pin 12 |
| 5 | RW | GND (write only) |
| 6 | E | Uno pin 11 |
| 7-10 | D0-D3 | not connected |
| 11 | D4 | Uno pin 5 |
| 12 | D5 | Uno pin 4 |
| 13 | D6 | Uno pin 3 |
| 14 | D7 | Uno pin 2 |
| 15 | A (backlight +) | 5V through a 220 ohm resistor |
| 16 | K (backlight -) | GND |

## Power notes

- Power the LCD and both pots from the Uno's 5V and GND pins (USB power is enough).
- Tie RW to GND. Because RW is never read, the firmware cannot detect a missing LCD: the boot self-test does not verify the display. If the screen shows only blocks or nothing after adjusting contrast, check VDD, V0 and the backlight wiring before debugging the firmware.
- Contrast: turn the pot until the top row shows solid blocks, then back off until text is clear.
- Dial direction: if turning the pot clockwise lowers the level, swap its two outer wires.
- Use a USB data cable, not a charge-only one.

## Pins to avoid

- 0 and 1: the Uno's USB serial link to the laptop. Anything wired there breaks uploads and the gateway connection.
- 13: the on-board LED, which blinks during boot. Fine for an output, not for a button.

## First power-up

The Uno resets when the serial port is opened (including by the gateway, which waits about 3 s before its first request). After flashing, the serial monitor should print `selftest: ok` and a `ram:` line, and the LCD should show `AIRLOCK  READY` with the dial position. Then run the smoke test (see [README.md](README.md)).
