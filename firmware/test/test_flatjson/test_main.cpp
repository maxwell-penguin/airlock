// Native unit tests for src/flatjson.h (the Uno key's JSON parser):  cd firmware && pio test -e native
// Request lines are copied from gateway/airlock/keyproto.encode_request output.
#include <unity.h>
#include <stdio.h>
#include <string.h>
#include "flatjson.h"

using namespace fj;

static char buf[512];
static Field f[MAX_FIELDS];

static uint8_t parse(const char *line) {
  strncpy(buf, line, sizeof buf - 1);
  buf[sizeof buf - 1] = 0;
  return parseFlat(buf, f);
}

void setUp() {}
void tearDown() {}

void test_gateway_request() {
  uint8_t n = parse("{\"type\":\"request\",\"action_id\":\"a1\",\"summary\":\"Open http://demo.local/clean.html\","
                    "\"nonce\":\"n1\",\"risk\":2}");
  TEST_ASSERT_EQUAL_UINT8(5, n);
  TEST_ASSERT_EQUAL_STRING("request", fieldStr(f, n, "type"));
  TEST_ASSERT_EQUAL_STRING("a1", fieldStr(f, n, "action_id"));
  TEST_ASSERT_EQUAL_STRING("Open http://demo.local/clean.html", fieldStr(f, n, "summary"));
  TEST_ASSERT_EQUAL_STRING("n1", fieldStr(f, n, "nonce"));
  const Field *risk = field(f, n, "risk");
  TEST_ASSERT_NOT_NULL(risk);
  TEST_ASSERT_NULL(risk->str);
  TEST_ASSERT_EQUAL_INT32(2, risk->num);
}

void test_escapes_are_unescaped() {  // quotes and backslashes, as json.dumps writes them
  uint8_t n = parse("{\"type\":\"request\",\"action_id\":\"a1b2c3d4e\","
                    "\"summary\":\"Send to boss@example.com: \\\"hi\\\" C:\\\\tmp\",\"nonce\":\"9f3c11aa9f3c11aa\",\"risk\":3}");
  TEST_ASSERT_EQUAL_UINT8(5, n);
  TEST_ASSERT_EQUAL_STRING("Send to boss@example.com: \"hi\" C:\\tmp", fieldStr(f, n, "summary"));
  TEST_ASSERT_EQUAL_STRING("9f3c11aa9f3c11aa", fieldStr(f, n, "nonce"));
}

void test_unicode_escape_ascii_only() {
  uint8_t n = parse("{\"s\":\"\\u0041\\u007e\"}");
  TEST_ASSERT_EQUAL_UINT8(1, n);
  TEST_ASSERT_EQUAL_STRING("A~", fieldStr(f, n, "s"));
  TEST_ASSERT_EQUAL_UINT8(0, parse("{\"s\":\"\\u00e9\"}"));  // non-ASCII: whole line rejected
  TEST_ASSERT_EQUAL_UINT8(0, parse("{\"s\":\"\\u0000\"}"));  // NUL would truncate the text
}

void test_cancel_and_whitespace() {
  uint8_t n = parse(" { \"type\" : \"cancel\" , \"action_id\" : \"a1\" } \r\n");
  TEST_ASSERT_EQUAL_UINT8(2, n);
  TEST_ASSERT_EQUAL_STRING("cancel", fieldStr(f, n, "type"));
  TEST_ASSERT_EQUAL_STRING("a1", fieldStr(f, n, "action_id"));
}

void test_gateway_autonomy_state() {  // keyproto.encode_autonomy_state("autonomous")
  uint8_t n = parse("{\"type\":\"autonomy_state\",\"level\":\"autonomous\"}\n");
  TEST_ASSERT_EQUAL_UINT8(2, n);
  TEST_ASSERT_EQUAL_STRING("autonomy_state", fieldStr(f, n, "type"));
  TEST_ASSERT_EQUAL_STRING("autonomous", fieldStr(f, n, "level"));
}

void test_missing_and_non_string_fields_read_as_empty() {
  uint8_t n = parse("{\"type\":\"request\",\"nonce\":7,\"ok\":true,\"x\":null}");
  TEST_ASSERT_EQUAL_UINT8(4, n);
  TEST_ASSERT_EQUAL_STRING("", fieldStr(f, n, "nonce"));   // a number is not a string
  TEST_ASSERT_EQUAL_STRING("", fieldStr(f, n, "summary"));  // absent
  TEST_ASSERT_NULL(field(f, n, "summary"));
}

void test_rejects_bad_input() {
  const char *bad[] = {
      "",
      "selftest: ok",
      "{}",
      "{\"type\":\"request\"",                   // unterminated object
      "{\"type\":\"request}",                    // unterminated string
      "{\"type\":\"request\"} trailing",
      "{\"type\":\"request\",}",
      "{\"a\":{\"b\":1}}",                         // nested object
      "{\"a\":[1]}",                              // array
      "{\"a\":1.5}",                              // decimal
      "{\"a\":\"\\q\"}",                          // unknown escape
      "{\"a\":\"\\u12\"}",                        // short \u escape
      "{\"a\" 1}",
      "{\"1\":1,\"2\":2,\"3\":3,\"4\":4,\"5\":5,\"6\":6,\"7\":7,\"8\":8,\"9\":9}",  // > MAX_FIELDS
  };
  for (const char *b : bad) {
    char msg[96];
    snprintf(msg, sizeof msg, "should reject: %s", b);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, parse(b), msg);
  }
}

void test_safe_token() {
  TEST_ASSERT_TRUE(safeToken("a1b2c3d4e", 24));
  TEST_ASSERT_TRUE(safeToken("smoke-ab_12", 24));
  TEST_ASSERT_FALSE(safeToken("", 24));
  TEST_ASSERT_FALSE(safeToken("a\"b", 24));    // would break the JSON the key writes
  TEST_ASSERT_FALSE(safeToken("a b", 24));
  TEST_ASSERT_FALSE(safeToken("abcde", 4));     // too long
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_gateway_request);
  RUN_TEST(test_escapes_are_unescaped);
  RUN_TEST(test_unicode_escape_ascii_only);
  RUN_TEST(test_cancel_and_whitespace);
  RUN_TEST(test_gateway_autonomy_state);
  RUN_TEST(test_missing_and_non_string_fields_read_as_empty);
  RUN_TEST(test_rejects_bad_input);
  RUN_TEST(test_safe_token);
  return UNITY_END();
}
