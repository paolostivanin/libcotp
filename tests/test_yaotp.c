#include <criterion/criterion.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/cotp.h"

// Known-answer vectors from KeeYaOtp/KeeYaOtp.Tests/YaotpTest.cs.
// Source of truth for YAOTP correctness — these exercise the full Yandex secret format
// (base32 with CRC-13) and pin lengths from KeeYaOtp's upstream test suite.
//
// Timestamps converted from the UTC strings in YaotpTest.cs:
//   2020-02-07T08:27:00Z -> 1581064020
//   2020-02-07T15:53:30Z -> 1581090810
//   2020-02-07T16:04:29Z -> 1581091469
//   2020-02-07T16:30:59Z -> 1581093059

static const char *kSecret4 = "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI";
static const char *kPin4    = "7586";

static const char *kSecret16 = "JBGSAU4G7IEZG6OY4UAXX62JU4AAAAAAHTSG4HXU3M";
static const char *kPin16    = "5210481216086702";

Test(yaotp, vector_pin4_t1) {
    cotp_error_t err = -1;
    char *code = get_yaotp_at (kSecret4, kPin4, 1581064020L, &err);
    cr_assert_not_null (code);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_str_eq (code, "oactmacq");
    free (code);
}

Test(yaotp, vector_pin4_t2) {
    cotp_error_t err = -1;
    char *code = get_yaotp_at (kSecret4, kPin4, 1581090810L, &err);
    cr_assert_not_null (code);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_str_eq (code, "wemdwrix");
    free (code);
}

Test(yaotp, vector_pin16_t1) {
    cotp_error_t err = -1;
    char *code = get_yaotp_at (kSecret16, kPin16, 1581091469L, &err);
    cr_assert_not_null (code);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_str_eq (code, "dfrpywob");
    free (code);
}

Test(yaotp, vector_pin16_t2) {
    cotp_error_t err = -1;
    char *code = get_yaotp_at (kSecret16, kPin16, 1581093059L, &err);
    cr_assert_not_null (code);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_str_eq (code, "vunyprpd");
    free (code);
}

Test(yaotp, pin_length_from_secret) {
    cotp_error_t err = -1;
    int n = cotp_yaotp_secret_pin_length (kSecret4, &err);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_eq (n, 4);

    err = -1;
    n = cotp_yaotp_secret_pin_length (kSecret16, &err);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_eq (n, 16);
}

Test(yaotp, output_shape) {
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp_at (kSecret4, kPin4, 1581064020L, &err);
    cr_assert_not_null (code);
    cr_expect_eq (strlen (code), 8);
    for (size_t i = 0; i < 8; i++) {
        cr_expect (code[i] >= 'a' && code[i] <= 'z', "char at %zu is not a-z: %c", i, code[i]);
    }
    free (code);
}

Test(yaotp, null_secret) {
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp_at (NULL, kPin4, 1581064020L, &err);
    cr_expect_null (code);
    cr_expect_eq (err, INVALID_USER_INPUT);
}

Test(yaotp, null_pin) {
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp_at (kSecret4, NULL, 1581064020L, &err);
    cr_expect_null (code);
    cr_expect_eq (err, INVALID_USER_INPUT);
}

Test(yaotp, wrong_pin_length) {
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp_at (kSecret4, "12345", 1581064020L, &err);
    cr_expect_null (code);
    cr_expect_eq (err, INVALID_YAOTP_PIN);
}

Test(yaotp, non_digit_pin) {
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp_at (kSecret4, "abcd", 1581064020L, &err);
    cr_expect_null (code);
    cr_expect_eq (err, INVALID_YAOTP_PIN);
}

Test(yaotp, non_base32_secret) {
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp_at ("!!!not-base32!!!", kPin4, 1581064020L, &err);
    cr_expect_null (code);
    cr_expect_eq (err, INVALID_B32_INPUT);
}

Test(yaotp, secret_too_short) {
    // "JBSWY3DPEHPK3PXP" is a valid base32 string but decodes to 10 bytes — well under the 26-byte minimum.
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp_at ("JBSWY3DPEHPK3PXP", kPin4, 1581064020L, &err);
    cr_expect_null (code);
    cr_expect_eq (err, INVALID_YAOTP_SECRET_LENGTH);
}

Test(yaotp, crc_invalid) {
    // Flip a bit in the key portion of kSecret4 — base32 stays valid, decoded length stays 26,
    // but the CRC-13 over the preceding bits no longer matches the stored 12-bit tail.
    // 'L' (10) -> 'M' (12) flips bit 1 of the first decoded byte.
    char tampered[64];
    snprintf (tampered, sizeof (tampered), "%s", kSecret4);
    tampered[0] = 'M';
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp_at (tampered, kPin4, 1581064020L, &err);
    cr_expect_null (code);
    cr_expect_eq (err, INVALID_YAOTP_SECRET_CRC);
}

Test(yaotp, ctx_wrappers) {
    cotp_ctx *ctx = cotp_ctx_create (8, 30, COTP_SHA256);
    cr_assert_not_null (ctx);

    cotp_error_t err = -1;
    char *code = cotp_ctx_yaotp_at (ctx, kSecret4, kPin4, 1581064020L, &err);
    cr_assert_not_null (code);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_str_eq (code, "oactmacq");
    free (code);

    err = NO_ERROR;
    code = cotp_ctx_yaotp_at (NULL, kSecret4, kPin4, 1581064020L, &err);
    cr_expect_null (code);
    cr_expect_eq (err, INVALID_USER_INPUT);

    cotp_ctx_free (ctx);
}

Test(yaotp, get_yaotp_returns_something) {
    // Smoke-test the wall-clock variant: we can't assert the value, only that it generates a code.
    cotp_error_t err = NO_ERROR;
    char *code = get_yaotp (kSecret4, kPin4, &err);
    cr_assert_not_null (code);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_eq (strlen (code), 8);
    free (code);
}
