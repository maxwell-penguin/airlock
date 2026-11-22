// Airlock approval key: Arduino Uno + LCD1602 + potentiometer + approve and deny buttons.
// Protocol: gateway/airlock/keyproto.py, docs/CONTRACTS.md §5. Pins and settings: config.h.
//   approve (tap)           -> signed {"type":"reply","decision":"approve"}, only once every page was shown
//   deny (tap)              -> signed {"type":"reply","decision":"deny"}, at any time
//   both buttons together   -> {"type":"panic"}
//   potentiometer (3 zones) -> signed {"type":"autonomy","level","seq"}
//   {"type":"autonomy_state","level"} from the gateway -> idle screen shows "mode <level>" (display only)
// Hardware-independent rules (crypto, paging, dial, buttons) are in keylogic.h and the message
// parser in flatjson.h; both are host-tested (pio test -e native). This file is the hardware side.
// The Uno has 2 KB of RAM: see the `ram:` line it prints, and keep it well above zero.
#include <Arduino.h>
#include <EEPROM.h>
#include <LiquidCrystal.h>
#include "config.h"
#include "flatjson.h"
#include "keylogic.h"

static_assert(sizeof(SHARED_SECRET) - 1 <= 64, "SHARED_SECRET longer than 64 bytes is not supported");

LiquidCrystal lcd(PIN_LCD_RS, PIN_LCD_E, PIN_LCD_D4, PIN_LCD_D5, PIN_LCD_D6, PIN_LCD_D7);

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------
const uint8_t ID_MAX = 24, NONCE_MAX = 40;
char pendingId[ID_MAX + 1], pendingNonce[NONCE_MAX + 1], pendingText[kl::SUMMARY_MAX + 1];
int pendingRisk = 0;
bool pending = false;
uint32_t pendingStart = 0;
uint32_t autonomySeq = 0;  // persisted in EEPROM so a reboot never reuses a seq
const int EEPROM_SEQ_ADDR = 0;
using kl::LEVEL_NAMES;
int dialShown = -1;        // the dial's current zone (shown on the idle screen until the gateway says which level is in force)
int gatewayLevel = -1;     // the level in force, from the gateway's autonomy_state message; -1 until the first one
uint32_t noticeUntil = 0;  // a short notice (APPROVED / DENIED / PANIC SENT) is on screen until then
bool selftestOk = true;
char selftestWhy[24] = "";

char lineBuf[256];  // one JSON line: a request is ~160 bytes, ~250 if every summary char is escaped
size_t lineLen = 0;
bool lineOverflow = false;

static bool seenAll() { return kl::allSeen(millis() - pendingStart, kl::pageCount(strlen(pendingText))); }

// ---------------------------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------------------------
static void lcdRow(uint8_t row, const char *s) {
  char buf[kl::PAGE_COLS + 1];
  snprintf(buf, sizeof buf, "%-16.16s", s);  // pad to 16 so no clear() (and no flicker) is needed
  lcd.setCursor(0, row);
  lcd.print(buf);
}

static void showMessage(const char *l1, const char *l2) { lcdRow(0, l1); lcdRow(1, l2); }

static void showIdle() {
  if (!selftestOk) { showMessage("SELFTEST FAIL", selftestWhy); return; }
  char b[kl::PAGE_COLS + 1];
  kl::idleRow(gatewayLevel, dialShown, b);
  showMessage("AIRLOCK  READY", b);
}

static void notice(const char *l1, const char *l2, uint32_t ms) {
  showMessage(l1, l2);
  noticeUntil = millis() + ms;
}

static const char *riskName(int r) {
  switch (r) {
    case 1: return "SAFE";
    case 2: return "REVERSIBLE";
    case 3: return "EXTERNAL";
    case 4: return "HARD STOP";
    default: return "UNKNOWN";
  }
}

static uint32_t lastFrameKey = 0xFFFFFFFF;

static void renderRequest() {
  uint32_t elapsed = millis() - pendingStart;
  size_t len = strlen(pendingText);
  uint8_t pages = kl::pageCount(len);
  kl::Frame f = kl::frameAt(elapsed, pages);
  uint32_t left = kl::secondsLeft(elapsed, APPROVAL_TIMEOUT_S);
  bool seen = kl::allSeen(elapsed, pages);
  uint32_t key = (uint32_t)f.kind | ((uint32_t)f.page << 4) | (f.kind == kl::FRAME_TEXT ? 0 : left << 8) | (seen ? 1UL << 30 : 0);
  if (key == lastFrameKey) return;  // only touch the LCD when something changed
  lastFrameKey = key;
  char a[kl::PAGE_COLS + 1], b[kl::PAGE_COLS + 1];
  if (f.kind == kl::FRAME_HEAD) {
    snprintf(a, sizeof a, "PAGE %u/%u RISK %d", f.page + 1, pages, pendingRisk);
    snprintf(b, sizeof b, "%-10s %3lus", riskName(pendingRisk), (unsigned long)left);
    showMessage(a, b);
  } else if (f.kind == kl::FRAME_TEXT) {
    for (uint8_t row = 0; row < kl::PAGE_ROWS; row++) {
      kl::pageRow(pendingText, len, f.page, row, a);
      lcdRow(row, a);
    }
  } else {
    snprintf(b, sizeof b, "%3lus left", (unsigned long)left);
    showMessage(seen ? "APPROVE or DENY" : "read all pages", b);
  }
}

// ---------------------------------------------------------------------------------------------
// RAM check. At boot the free gap between heap and stack is filled with a marker; ramNeverUsed()
// returns the longest run still intact, i.e. memory nothing has touched since boot. Printed as a
// plain line (not JSON, so the gateway ignores it) after the self-test, each reply and each cancel.
// ---------------------------------------------------------------------------------------------
extern uint8_t __heap_start, *__brkval;
const uint8_t RAM_MARK = 0xC5;

static void paintFreeRam() {
  uint8_t here;
  uint8_t *start = __brkval ? __brkval : &__heap_start;
  for (uint8_t *p = start; p < &here - 64; p++) *p = RAM_MARK;  // keep clear of this frame
}

static unsigned ramNeverUsed() {
  unsigned best = 0, run = 0;
  for (uint8_t *p = &__heap_start; p < (uint8_t *)SP; p++) {
    run = (*p == RAM_MARK) ? run + 1 : 0;
    if (run > best) best = run;
  }
  return best;
}

static void printRam() {
  Serial.print(F("ram: "));
  Serial.print(ramNeverUsed());
  Serial.println(F(" bytes never used"));
}

// ---------------------------------------------------------------------------------------------
// Protocol. Input is parsed by flatjson.h. Every value sent is a fixed word, lowercase hex, a
// number, or an action_id that passed fj::safeToken(), so the output needs no JSON escaping.
// ---------------------------------------------------------------------------------------------
static void sendField(const __FlashStringHelper *key, const char *val, bool last) {
  Serial.print('"');
  Serial.print(key);
  Serial.print(F("\":\""));
  Serial.print(val);
  Serial.print(last ? F("\"}\n") : F("\","));
}

static void endRequest() {
  pending = false;
  lastFrameKey = 0xFFFFFFFF;
}

__attribute__((noinline)) static void reply(const char *decision) {
  char dg[17], mac[65];
  kl::digest16(pendingText, dg);  // the FULL text, never a page
  kl::replyHmac(SHARED_SECRET, pendingId, decision, pendingNonce, dg, mac);
  Serial.print(F("{\"type\":\"reply\","));
  sendField(F("action_id"), pendingId, false);
  sendField(F("decision"), decision, false);
  sendField(F("digest"), dg, false);
  sendField(F("hmac"), mac, true);
  endRequest();
  notice(strcmp(decision, "approve") == 0 ? "APPROVED" : "DENIED", "reply sent", 1500);
  printRam();
}

static bool printableAscii(const char *s) {
  for (; *s; s++) if (*s < 32 || *s > 126) return false;
  return true;
}

__attribute__((noinline)) static void handleLine(char *line) {
  fj::Field f[fj::MAX_FIELDS];
  uint8_t n = fj::parseFlat(line, f);
  if (!n) return;  // not JSON, or not a shape this protocol uses: ignore
  const char *type = fj::fieldStr(f, n, "type");
  if (strcmp(type, "request") == 0) {
    const char *id = fj::fieldStr(f, n, "action_id");
    const char *nonce = fj::fieldStr(f, n, "nonce");
    const char *summary = fj::fieldStr(f, n, "summary");
    const fj::Field *risk = fj::field(f, n, "risk");
    // Anything we cannot show or sign exactly is ignored: the gateway then times out, which is deny.
    if (!fj::safeToken(id, ID_MAX) || !*nonce || strlen(nonce) > NONCE_MAX) return;
    if (strlen(summary) > kl::SUMMARY_MAX || !printableAscii(summary)) return;
    strcpy(pendingId, id);
    strcpy(pendingNonce, nonce);
    strcpy(pendingText, summary);
    pendingRisk = risk && !risk->str ? (int)risk->num : 0;
    pending = true;  // a new request replaces the one on screen
    pendingStart = millis();
    lastFrameKey = 0xFFFFFFFF;
    noticeUntil = 0;
  } else if (strcmp(type, "cancel") == 0) {
    // Resolved elsewhere (dashboard, timeout). Only react to the request on screen.
    if (pending && strcmp(pendingId, fj::fieldStr(f, n, "action_id")) == 0) { endRequest(); showIdle(); printRam(); }
  } else if (strcmp(type, "autonomy_state") == 0) {
    // Display only: the level in force, however it was set. Never sent back, never changes what the buttons or dial do.
    int lvl = kl::levelIndex(fj::fieldStr(f, n, "level"));
    if (lvl < 0) return;  // unknown level: keep showing the last one
    gatewayLevel = lvl;
    if (!pending && millis() >= noticeUntil) showIdle();  // during a request or a notice, the idle screen picks it up later
  }
}

static void pollSerial() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n') {
      lineBuf[lineLen] = 0;
      if (!lineOverflow) handleLine(lineBuf);  // a line too long to hold is dropped whole
      lineLen = 0;
      lineOverflow = false;
    } else if (c != '\r') {
      if (lineLen < sizeof lineBuf - 1) lineBuf[lineLen++] = c;
      else lineOverflow = true;
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Buttons: debounced here; what a press means is decided by kl::ButtonRules (host-tested).
// ---------------------------------------------------------------------------------------------
const uint32_t DEBOUNCE_MS = 30;

struct Button {
  uint8_t pin;
  bool down;      // debounced
  bool lastRaw;
  uint32_t changedAt;
  bool released;  // true for one poll after a debounced release

  bool read() { return kl::buttonPressed(digitalRead(pin), BUTTON_ACTIVE_HIGH); }  // either wiring, see config.h

  void begin() {
    pinMode(pin, BUTTON_PIN_MODE);
    lastRaw = read();
    down = lastRaw;
    changedAt = 0;
    released = false;
  }

  void poll() {
    released = false;
    bool raw = read();
    if (raw != lastRaw) { lastRaw = raw; changedAt = millis(); }
    if (raw != down && millis() - changedAt >= DEBOUNCE_MS) {
      down = raw;
      if (!down) released = true;
    }
  }
};

Button approveBtn = {PIN_BTN_APPROVE};
Button denyBtn = {PIN_BTN_DENY};
kl::ButtonRules buttonRules;

static void pollButtons() {
  approveBtn.poll();
  denyBtn.poll();
  switch (buttonRules.step(approveBtn.down, denyBtn.down, approveBtn.released, denyBtn.released, pending,
                           pending && seenAll())) {
    case kl::ACT_PANIC:
      Serial.print(F("{\"type\":\"panic\"}\n"));
      notice("PANIC SENT", "agent frozen", 2000);
      break;
    case kl::ACT_APPROVE: reply("approve"); break;
    case kl::ACT_DENY: reply("deny"); break;
    default: break;
  }
}

// ---------------------------------------------------------------------------------------------
// Dial: 3 zones. A new zone must hold DIAL_SETTLE_MS before it is announced. Not announced on boot.
// ---------------------------------------------------------------------------------------------
__attribute__((noinline)) static void pollDial() {
  static int announced = -1, candidate = -1;
  static uint32_t candSince = 0;
  int zone = kl::dialZone(analogRead(PIN_DIAL), ADC_MAX);
  if (announced < 0) { announced = candidate = dialShown = zone; return; }
  if (zone != candidate) { candidate = zone; candSince = millis(); return; }
  if (zone == announced || millis() - candSince < DIAL_SETTLE_MS) return;  // ignore jitter at zone edges
  announced = dialShown = zone;
  autonomySeq++;
  EEPROM.put(EEPROM_SEQ_ADDR, autonomySeq);  // persist before sending so a reboot never reuses a seq
  char mac[65], num[11];
  kl::autonomyHmac(SHARED_SECRET, LEVEL_NAMES[zone], autonomySeq, mac);
  kl::u32ToDec(autonomySeq, num);
  Serial.print(F("{\"type\":\"autonomy\",\"level\":\""));
  Serial.print(LEVEL_NAMES[zone]);
  Serial.print(F("\",\"seq\":"));
  Serial.print(num);  // a JSON number, as the gateway expects
  Serial.print(F(",\"hmac\":\""));
  Serial.print(mac);
  Serial.print(F("\"}\n"));
  if (!pending && millis() >= noticeUntil) showIdle();
}

// ---------------------------------------------------------------------------------------------
// Boot self-test: both buttons at their idle level (HIGH for pull-up switches, LOW for button
// modules), dial in range, SHA-256 and contract vectors.
// ---------------------------------------------------------------------------------------------
static void fail(const char *why) {
  selftestOk = false;
  if (selftestWhy[0]) strlcat(selftestWhy, ",", sizeof selftestWhy);
  strlcat(selftestWhy, why, sizeof selftestWhy);
}

__attribute__((noinline)) static void runSelfTest() {
  const int idle = kl::buttonIdleLevel(BUTTON_ACTIVE_HIGH);
  if (digitalRead(PIN_BTN_APPROVE) != idle) fail("approve");
  if (digitalRead(PIN_BTN_DENY) != idle) fail("deny");
  int raw = analogRead(PIN_DIAL);
  if (raw < 0 || raw > ADC_MAX) fail("dial");
  char hex[65], dg[17];
  kl::shaHex("abc", hex);
  if (strcmp_P(hex, PSTR("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) != 0) fail("sha");
  // Vectors from docs/CONTRACTS.md. The digest does not depend on the secret; the HMAC vectors do.
  const char *text = "Open http://demo.local/clean.html";
  kl::digest16(text, dg);
  if (strcmp_P(dg, PSTR("27542041f4fde83e")) != 0) fail("digest");
  if (strcmp(SHARED_SECRET, "dev-secret-change-me") == 0) {
    kl::replyHmac(SHARED_SECRET, "a1b2c3", "approve", "9f3c11aa", dg, hex);
    if (strcmp_P(hex, PSTR("5a2ab9c954f905d9b6f9ebcb737dab6180ce07d90b984b580a4cd7f52625d2b3")) != 0) fail("hmac");
    kl::autonomyHmac(SHARED_SECRET, "autonomous", 1, hex);
    if (strcmp_P(hex, PSTR("ce8c487361c493401946d2eb484a3b4cc69a9b724e6aeb72603dc45e19448129")) != 0) fail("autohmac");
  }
  // Not JSON, so the gateway ignores these lines.
  if (selftestOk) Serial.println(F("selftest: ok"));
  else { Serial.print(F("selftest: FAIL (")); Serial.print(selftestWhy); Serial.println(')'); }
}

void setup() {
  paintFreeRam();
  Serial.begin(115200);
  approveBtn.begin();
  denyBtn.begin();
  lcd.begin(kl::PAGE_COLS, kl::PAGE_ROWS);
  lcd.clear();
  delay(50);  // let the pull-ups (or the module's pull-downs) settle before the idle-level check
  EEPROM.get(EEPROM_SEQ_ADDR, autonomySeq);
  if (autonomySeq == 0xFFFFFFFFUL) autonomySeq = 0;  // fresh EEPROM reads all ones
  runSelfTest();
  printRam();
  pollDial();  // records the starting zone (not announced)
  showIdle();
}

void loop() {
  pollSerial();
  pollButtons();
  pollDial();
  if (pending && kl::timedOut(millis() - pendingStart, APPROVAL_TIMEOUT_S)) {
    endRequest();  // the gateway denies on its own timeout; just clear the screen
    showIdle();
  }
  if (noticeUntil && millis() >= noticeUntil) {
    noticeUntil = 0;
    lastFrameKey = 0xFFFFFFFF;
    if (!pending) showIdle();
  }
  if (pending && !noticeUntil) renderRequest();
}
