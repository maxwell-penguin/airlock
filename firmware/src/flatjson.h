// Minimal JSON for the Uno key (env uno_lcd): parses one flat object of string / integer values
// in place. No Arduino includes, so it compiles on the host for `pio test -e native`.
// The gateway sends compact one-level objects (keyproto.encode_request, cancel). Strings are
// unescaped inside the input buffer, so parsing needs no extra RAM. Anything else (nesting,
// \u escapes outside ASCII, bad syntax, too many fields) makes parseFlat return 0, and the
// caller ignores the whole line.
#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace fj {

struct Field {
  const char *key;
  const char *str;  // null if the value is not a string
  long num;
};
constexpr uint8_t MAX_FIELDS = 8;

inline char *skipWs(char *p) {
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  return p;
}

inline int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// p points just after the opening quote. Unescapes in place; returns the char after the closing
// quote, or null on error.
inline char *parseString(char *p, const char **out) {
  char *w = p;
  *out = p;
  while (*p != '"') {
    if (!*p) return nullptr;
    if (*p != '\\') { *w++ = *p++; continue; }
    p++;
    switch (*p) {
      case '"': case '\\': case '/': *w++ = *p++; break;
      case 'b': *w++ = '\b'; p++; break;
      case 'f': *w++ = '\f'; p++; break;
      case 'n': *w++ = '\n'; p++; break;
      case 'r': *w++ = '\r'; p++; break;
      case 't': *w++ = '\t'; p++; break;
      case 'u': {
        int v = 0;
        for (uint8_t i = 1; i <= 4; i++) {
          int h = hexVal(p[i]);
          if (h < 0) return nullptr;
          v = v * 16 + h;
        }
        if (v == 0 || v > 127) return nullptr;  // the key only shows ASCII
        *w++ = (char)v;
        p += 5;
        break;
      }
      default: return nullptr;
    }
  }
  *w = 0;  // w <= p, so this never overwrites unread input
  return p + 1;
}

inline uint8_t parseFlat(char *p, Field *f) {  // number of fields, or 0 on any error
  uint8_t n = 0;
  p = skipWs(p);
  if (*p++ != '{') return 0;
  p = skipWs(p);
  if (*p == '}') return 0;
  for (;;) {
    if (n == MAX_FIELDS || *p++ != '"') return 0;
    if (!(p = parseString(p, &f[n].key))) return 0;
    p = skipWs(p);
    if (*p++ != ':') return 0;
    p = skipWs(p);
    f[n].str = nullptr;
    f[n].num = 0;
    if (*p == '"') {
      if (!(p = parseString(p + 1, &f[n].str))) return 0;
    } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
      char *e;
      f[n].num = strtol(p, &e, 10);
      if (e == p) return 0;
      p = e;
    } else if (!strncmp(p, "true", 4)) p += 4;
    else if (!strncmp(p, "false", 5)) p += 5;
    else if (!strncmp(p, "null", 4)) p += 4;
    else return 0;  // objects, arrays, decimals: not part of this protocol
    n++;
    p = skipWs(p);
    if (*p == '}') break;
    if (*p++ != ',') return 0;
    p = skipWs(p);
  }
  return *skipWs(p + 1) == 0 ? n : 0;
}

inline const Field *field(const Field *f, uint8_t n, const char *key) {
  for (uint8_t i = 0; i < n; i++) if (!strcmp(f[i].key, key)) return &f[i];
  return nullptr;
}

inline const char *fieldStr(const Field *f, uint8_t n, const char *key) {
  const Field *x = field(f, n, key);
  return x && x->str ? x->str : "";
}

inline bool safeToken(const char *s, size_t maxLen) {  // [A-Za-z0-9_-], 1..maxLen chars
  size_t n = 0;
  for (; *s; s++, n++) {
    char c = *s;
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
  }
  return n > 0 && n <= maxLen;
}

}  // namespace fj
