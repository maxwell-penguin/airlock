#pragma once
// Pins and settings for the Airlock key: Arduino Uno + LCD1602 (HD44780, 4-bit parallel).
// This file is the source of truth for pins; firmware/WIRING.md explains them.

#define PIN_LCD_RS 12
#define PIN_LCD_E 11
#define PIN_LCD_D4 5
#define PIN_LCD_D5 4
#define PIN_LCD_D6 3
#define PIN_LCD_D7 2
#define PIN_BTN_APPROVE 7   // press = approve (wiring: see BUTTON_ACTIVE_HIGH below)
#define PIN_BTN_DENY 8      // press = deny; both buttons together = panic
#define PIN_DIAL A2         // potentiometer wiper, ends on 5V and GND
#define ADC_MAX 1023        // 10-bit ADC

#define DIAL_SETTLE_MS 300  // a new dial zone must hold this long before it is announced

// Button polarity, selected by a build flag (default off):
//   BUTTON_ACTIVE_HIGH=0 (default)  bare switch, other leg to GND, pinMode INPUT_PULLUP, idle HIGH, pressed LOW
//   -DBUTTON_ACTIVE_HIGH=1          button MODULE (VCC, GND, OUT with an on-board pull-down), pinMode INPUT,
//                                   idle LOW, pressed HIGH. Env uno_lcd_module builds this. VCC to the Uno's 5V.
// The polarity rules live in keylogic.h (kl::buttonPressed, kl::buttonIdleLevel) so they are unit-tested on the host.
#ifndef BUTTON_ACTIVE_HIGH
#define BUTTON_ACTIVE_HIGH 0
#endif
#if BUTTON_ACTIVE_HIGH
#define BUTTON_PIN_MODE INPUT  // the module drives the pin both ways; an internal pull-up would fight its pull-down
#else
#define BUTTON_PIN_MODE INPUT_PULLUP
#endif

// Must equal AIRLOCK_APPROVAL_TIMEOUT on the gateway (default 60). The device cannot read the
// gateway's setting, so keep them in step; pass -DAPPROVAL_TIMEOUT_S=<n> to change it per build.
#ifndef APPROVAL_TIMEOUT_S
#define APPROVAL_TIMEOUT_S 60
#endif

// Must equal AIRLOCK_KEY_SECRET on the gateway (at most 64 bytes). Demo only: do not commit a real secret.
#define SHARED_SECRET "dev-secret-change-me"
