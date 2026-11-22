// Airlock key: hardware-independent logic (SHA-256, HMAC, digest, paging, dial, timeout, buttons).
// No Arduino code and no C++ standard library (the Uno has neither), so the same file runs on the
// board and on the host for `pio test -e native`.
// Protocol source of truth: gateway/airlock/keyproto.py. Do not change these rules without
// changing keyproto.py, docs/CONTRACTS.md and the test vectors together.
//   digest        = first 16 hex of SHA-256 of the FULL displayed text (never per page)
//   reply HMAC    = HMAC-SHA256(secret, "action_id|decision|nonce|digest")
//   autonomy HMAC = HMAC-SHA256(secret, "autonomy|level|seq")
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__AVR__)
#include <avr/pgmspace.h>
#define KL_PROGMEM PROGMEM
#define KL_READ32(p) pgm_read_dword(p)
#define KL_MEMCPY_P(d, s, n) memcpy_P(d, s, n)
#else
#define KL_PROGMEM
#define KL_READ32(p) (*(p))
#define KL_MEMCPY_P(d, s, n) memcpy(d, s, n)
#endif
// Separate stack frames for the crypto helpers: inlined together they overflow the Uno's 2 KB.
#define KL_NOINLINE __attribute__((noinline))

namespace kl {

// ---------------------------------------------------------------------------------------------
// SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), streaming, small RAM footprint.
// ---------------------------------------------------------------------------------------------
static const uint32_t K[64] KL_PROGMEM = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static const uint32_t H0[8] KL_PROGMEM = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

inline uint32_t rotr(uint32_t x, uint8_t n) { return (x >> n) | (x << (32 - n)); }

struct Sha256 {
  uint32_t h[8];
  uint8_t buf[64];
  uint8_t used;
  uint32_t total;  // bytes hashed so far (messages here are tiny)

  void begin() {
    KL_MEMCPY_P(h, H0, sizeof h);
    used = 0;
    total = 0;
  }

  void block() {
    uint32_t w[16];  // rolling message schedule: w[i & 15]
    for (uint8_t i = 0; i < 16; i++)
      w[i] = (uint32_t)buf[4 * i] << 24 | (uint32_t)buf[4 * i + 1] << 16 | (uint32_t)buf[4 * i + 2] << 8 | buf[4 * i + 3];
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (uint8_t i = 0; i < 64; i++) {
      if (i >= 16) {
        uint32_t x = w[(i + 1) & 15], y = w[(i + 14) & 15];
        w[i & 15] += (rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)) + w[(i + 9) & 15] + (rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10));
      }
      uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + KL_READ32(&K[i]) + w[i & 15];
      uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  void update(const uint8_t *p, size_t n) {
    total += n;
    while (n--) {
      buf[used++] = *p++;
      if (used == 64) { block(); used = 0; }
    }
  }
  void update(const char *s) { update((const uint8_t *)s, strlen(s)); }

  void finish(uint8_t out[32]) {
    uint32_t bits = total * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    pad = 0;
    while (used != 56) update(&pad, 1);
    uint8_t len[8] = {0, 0, 0, 0, (uint8_t)(bits >> 24), (uint8_t)(bits >> 16), (uint8_t)(bits >> 8), (uint8_t)bits};
    update(len, 8);
    for (uint8_t i = 0; i < 8; i++) {
      out[4 * i] = h[i] >> 24; out[4 * i + 1] = h[i] >> 16; out[4 * i + 2] = h[i] >> 8; out[4 * i + 3] = h[i];
    }
  }
};

// The secret must be at most 64 bytes (the Uno build checks this at compile time), so the HMAC
// key block is the secret zero-padded to 64. It is read from the secret, not copied, to save RAM.
struct HmacSha256 {
  Sha256 sha;
  const char *secret;
  uint8_t secretLen;

  void padKey(uint8_t pad) {
    for (uint8_t i = 0; i < 64; i++) {
      uint8_t b = (i < secretLen ? (uint8_t)secret[i] : 0) ^ pad;
      sha.update(&b, 1);
    }
  }
  void begin(const char *s) {
    secret = s;
    secretLen = strlen(s);
    sha.begin();
    padKey(0x36);
  }
  void update(const char *s) { sha.update(s); }
  void finish(uint8_t out[32]) {  // one Sha256 serves the inner and the outer pass
    sha.finish(out);
    uint8_t ih[32];
    memcpy(ih, out, 32);
    sha.begin();
    padKey(0x5c);
    sha.update(ih, 32);
    sha.finish(out);
  }
};

inline void toHex(const uint8_t *b, uint8_t n, char *out) {  // out holds 2n + 1
  static const char hx[] = "0123456789abcdef";
  for (uint8_t i = 0; i < n; i++) { out[2 * i] = hx[b[i] >> 4]; out[2 * i + 1] = hx[b[i] & 15]; }
  out[2 * n] = 0;
}

inline void u32ToDec(uint32_t v, char out[11]) {
  char tmp[11];
  uint8_t n = 0;
  do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  for (uint8_t i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
  out[n] = 0;
}

// Full SHA-256 of text as 64 hex chars (self-test).
KL_NOINLINE inline void shaHex(const char *text, char out[65]) {
  Sha256 s;
  uint8_t d[32];
  s.begin();
  s.update(text);
  s.finish(d);
  toHex(d, 32, out);
}

// digest = first 16 hex of SHA-256 of the FULL displayed text (never per page)
KL_NOINLINE inline void digest16(const char *text, char out[17]) {
  Sha256 s;
  uint8_t d[32];
  s.begin();
  s.update(text);
  s.finish(d);
  toHex(d, 8, out);
}

// reply HMAC = HMAC-SHA256(secret, "action_id|decision|nonce|digest"); dg is digest16() of the text.
KL_NOINLINE inline void replyHmac(const char *secret, const char *id, const char *decision, const char *nonce,
                                  const char *dg, char out[65]) {
  HmacSha256 m;
  uint8_t mac[32];
  m.begin(secret);
  m.update(id); m.update("|"); m.update(decision); m.update("|"); m.update(nonce); m.update("|"); m.update(dg);
  m.finish(mac);
  toHex(mac, 32, out);
}

// autonomy HMAC = HMAC-SHA256(secret, "autonomy|level|seq")
KL_NOINLINE inline void autonomyHmac(const char *secret, const char *level, uint32_t seq, char out[65]) {
  char num[11];
  u32ToDec(seq, num);
  HmacSha256 m;
  uint8_t mac[32];
  m.begin(secret);
  m.update("autonomy|"); m.update(level); m.update("|"); m.update(num);
  m.finish(mac);
  toHex(mac, 32, out);
}

// ---------------------------------------------------------------------------------------------
// LCD paging: 16 columns x 2 rows = 32 characters per page, hard-wrapped.
// For each page a header frame ("PAGE n/N", risk, countdown) then the text frame; after the last
// page a footer frame; then repeat.
// ---------------------------------------------------------------------------------------------
const uint8_t PAGE_COLS = 16, PAGE_ROWS = 2, PAGE_CHARS = PAGE_COLS * PAGE_ROWS;
const uint32_t HEAD_MS = 800, TEXT_MS = 2000, FOOT_MS = 1200, PAGE_MS = HEAD_MS + TEXT_MS;
const uint8_t SUMMARY_MAX = 84;  // keyproto.SUMMARY_MAX: at most 3 pages

inline uint8_t pageCount(size_t len) { return len == 0 ? 1 : (uint8_t)((len + PAGE_CHARS - 1) / PAGE_CHARS); }

// One row of one page, unpadded, into out (17 bytes). Concatenating all rows gives back the text.
inline void pageRow(const char *text, size_t len, uint8_t page, uint8_t row, char out[PAGE_COLS + 1]) {
  size_t off = (size_t)page * PAGE_CHARS + (size_t)row * PAGE_COLS;
  out[0] = 0;
  if (off >= len) return;
  size_t n = len - off < PAGE_COLS ? len - off : PAGE_COLS;
  memcpy(out, text + off, n);
  out[n] = 0;
}

enum FrameKind { FRAME_HEAD, FRAME_TEXT, FRAME_FOOT };
struct Frame { FrameKind kind; uint8_t page; };

inline Frame frameAt(uint32_t elapsedMs, uint8_t pages) {
  uint32_t cycle = (uint32_t)pages * PAGE_MS + FOOT_MS;
  uint32_t p = elapsedMs % cycle;
  Frame f;
  if (p >= (uint32_t)pages * PAGE_MS) { f.kind = FRAME_FOOT; f.page = pages - 1; return f; }
  f.kind = (p % PAGE_MS) < HEAD_MS ? FRAME_HEAD : FRAME_TEXT;
  f.page = (uint8_t)(p / PAGE_MS);
  return f;
}

// True once every page's text frame has been on screen for its full time.
inline bool allSeen(uint32_t elapsedMs, uint8_t pages) { return elapsedMs >= (uint32_t)pages * PAGE_MS; }

// ---------------------------------------------------------------------------------------------
// Timeout, dial
// ---------------------------------------------------------------------------------------------
inline bool timedOut(uint32_t elapsedMs, uint32_t timeoutS) { return elapsedMs >= timeoutS * 1000UL; }
inline uint32_t secondsLeft(uint32_t elapsedMs, uint32_t timeoutS) {
  uint32_t total = timeoutS * 1000UL;
  return elapsedMs >= total ? 0 : (total - elapsedMs + 999) / 1000;
}

// 3 zones over the ADC range: 0 supervised, 1 balanced, 2 autonomous.
inline uint8_t dialZone(int raw, int adcMax) {
  long z = (long)raw * 3 / ((long)adcMax + 1);
  return z < 0 ? 0 : (z > 2 ? 2 : (uint8_t)z);
}

// Autonomy level names, indexed like the dial zones. They are the protocol's words (keyproto, docs/CONTRACTS.md).
static const char *const LEVEL_NAMES[3] = {"supervised", "balanced", "autonomous"};

// Index of a level name from the gateway's autonomy_state message, or -1 if it is not exactly one of the three.
inline int levelIndex(const char *name) {
  for (int i = 0; i < 3; i++)
    if (strcmp(name, LEVEL_NAMES[i]) == 0) return i;
  return -1;
}

// Second row of the idle screen. Once the gateway has said which level is in force ("mode balanced") that is shown, because
// it is the truth wherever the level was set (dashboard, dial, startup). Before that, the dial's zone ("dial balanced").
// gatewayLevel and dialZone are indexes into LEVEL_NAMES, or -1 for unknown.
inline void idleRow(int gatewayLevel, int dialZone, char out[PAGE_COLS + 1]) {
  int lvl = gatewayLevel >= 0 && gatewayLevel < 3 ? gatewayLevel : dialZone;
  strcpy(out, gatewayLevel >= 0 && gatewayLevel < 3 ? "mode " : "dial ");
  strcat(out, lvl >= 0 && lvl < 3 ? LEVEL_NAMES[lvl] : "?");  // longest: "mode autonomous", 15 chars
}

// ---------------------------------------------------------------------------------------------
// Button polarity (the only place it is decided).
// Bare switch to GND with INPUT_PULLUP: idle HIGH, pressed LOW (activeHigh = false, the default).
// Button module (VCC, GND, OUT) with its own pull-down, pin mode INPUT: idle LOW, pressed HIGH (activeHigh = true).
// `level` is what digitalRead returned (0 = LOW, anything else = HIGH). The rules below do not depend on polarity.
// ---------------------------------------------------------------------------------------------
inline bool buttonPressed(int level, bool activeHigh) { return activeHigh ? level != 0 : level == 0; }
inline int buttonIdleLevel(bool activeHigh) { return activeHigh ? 0 : 1; }  // what the boot self-test expects to read

// ---------------------------------------------------------------------------------------------
// Buttons. Approve and deny act on release, so a press that turns into "both at once" never
// sends a reply first. Both buttons down together is panic, sent once; then neither button does
// anything until both are released. Approve counts only once every page was shown (seen).
// ---------------------------------------------------------------------------------------------
enum Action { ACT_NONE, ACT_APPROVE, ACT_DENY, ACT_PANIC };

struct ButtonRules {
  bool combo = false;  // both buttons were down together during the current press

  // Inputs are debounced: *Down = held now, *Released = released since the last step.
  Action step(bool approveDown, bool denyDown, bool approveReleased, bool denyReleased, bool pending, bool seen) {
    Action a = ACT_NONE;
    if (approveDown && denyDown && !combo) {
      combo = true;
      a = ACT_PANIC;
    } else if (!combo && pending) {
      if (approveReleased && seen) a = ACT_APPROVE;
      else if (denyReleased) a = ACT_DENY;
    }
    if (!approveDown && !denyDown) combo = false;
    return a;
  }
};

}  // namespace kl
