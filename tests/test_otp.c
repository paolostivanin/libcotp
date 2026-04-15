#include <criterion/criterion.h>
#include <string.h>
#include "../src/cotp.h"

Test(totp_rfc6238, test_8_digits_sha1) {
    const char *K = "12345678901234567890";
    const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
    const char *expected_totp[] = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp;
    for (int i = 0; i < 6; i++) {
        totp = get_totp_at (K_base32, counter[i], 8, 30, COTP_SHA1, &err);
        cr_expect_str_eq (totp, expected_totp[i], "Expected %s to be equal to %s\n", totp, expected_totp[i]);
        free (totp);
    }
    free (K_base32);
}


Test(totp_rfc6238, test_8_digits_sha1_toint) {
    const char *K = "12345678901234567890";
    const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
    const int64_t expected_totp[] = {94287082, 7081804, 14050471, 89005924, 69279037, 65353130};

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    for (int i = 0; i < 6; i++) {
        char *totp_str = get_totp_at (K_base32, counter[i], 8, 30, COTP_SHA1, &err);
        int64_t totp = otp_to_int (totp_str, &err);
        cr_expect_eq (totp, expected_totp[i], "Expected %08ld to be equal to %08ld\n", totp, expected_totp[i]);
        free (totp_str);
    }
    free (K_base32);
}


Test(totp_rfc6238, test_10_digits_sha1) {
    const char *K = "12345678901234567890";
    const long counter = 1234567890;
    const char *expected_totp = "0689005924";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, counter, 10, 30, COTP_SHA1, &err);
    cr_expect_str_eq (totp, expected_totp, "Expected %s to be equal to %s\n", totp, expected_totp);
    free (totp);
    free (K_base32);
}


Test(totp_rfc6238, test_10_digits_sha1_toint) {
    const char *K = "12345678901234567890";
    const long counter = 1234567890;
    int64_t expected_totp = 689005924;

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp_str = get_totp_at (K_base32, counter, 10, 30, COTP_SHA1, &err);
    int64_t totp = otp_to_int (totp_str, &err);
    cr_expect_eq (totp, expected_totp, "Expected %010ld to be equal to %010ld\n", totp, expected_totp);

    free (totp_str);
    free (K_base32);
}


Test(totp_rfc6238, test_8_digits_sha256) {
    const char *K = "12345678901234567890123456789012";
    const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
    const char *expected_totp[] = {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"};

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp;
    for (int i = 0; i < 6; i++) {
        totp = get_totp_at (K_base32, counter[i], 8, 30, COTP_SHA256, &err);
        cr_expect_str_eq (totp, expected_totp[i], "Expected %s to be equal to %s\n", totp, expected_totp[i]);
        free (totp);
    }
    free (K_base32);
}


Test(totp_rfc6238, test_8_digits_sha512) {
    const char *K = "1234567890123456789012345678901234567890123456789012345678901234";
    const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
    const char *expected_totp[] = {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"};

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen (K) + 1, &cotp_err);

    cotp_error_t err;
    char *totp;
    for (int i = 0; i < 6; i++) {
        totp = get_totp_at (K_base32, counter[i], 8, 30, COTP_SHA512, &err);
        cr_expect_str_eq (totp, expected_totp[i], "Expected %s to be equal to %s\n", totp, expected_totp[i]);
        free (totp);
    }
    free (K_base32);
}


Test(hotp_rfc, test_6_digits) {
    const char *K = "12345678901234567890";
    const int counter[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const char *expected_hotp[] = {"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"};

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *hotp;
    for (int i = 0; i < 10; i++) {
        hotp = get_hotp (K_base32, counter[i], 6, COTP_SHA1, &err);
        cr_expect_str_eq (hotp, expected_hotp[i], "Expected %s to be equal to %s\n", hotp, expected_hotp[i]);
        free (hotp);
    }
    free (K_base32);
}


Test(hotp_rfc, test_wrong_digits_2) {
    const char *K = "this is a secret";

    cotp_error_t err;
    char *totp = get_totp (K, 2, 30, COTP_SHA1, &err);

    cr_expect_eq (err, INVALID_DIGITS, "Expected %d to be equal to %d\n", err, INVALID_DIGITS);
    cr_assert_null (totp);

    free (totp);
}


Test(hotp_rfc, test_wrong_digits_16) {
    const char *K = "this is a secret";

    cotp_error_t err;
    char *totp = get_totp (K, 16, 30, COTP_SHA1, &err);

    cr_expect_eq (err, INVALID_DIGITS, "Expected %d to be equal to %d\n", err, INVALID_DIGITS);
    cr_assert_null (totp);

    free (totp);
}


Test(hotp_rfc, test_period_zero) {
    const char *K = "this is a secret";

    cotp_error_t err;
    char *totp = get_totp (K, 6, 0, COTP_SHA1, &err);

    cr_expect_eq (err, INVALID_PERIOD, "Expected %d to be equal to %d\n", err, INVALID_PERIOD);
    cr_assert_null (totp);

    free (totp);
}


Test(hotp_rfc, test_totp_wrong_negative) {
    const char *K = "this is a secret";

    cotp_error_t err;
    char *totp = get_totp (K, 6, -20, COTP_SHA1, &err);

    cr_expect_eq (err, INVALID_PERIOD, "Expected %d to be equal to %d\n", err, INVALID_PERIOD);
    cr_assert_null (totp);

    free (totp);
}


Test(hotp_rfc, test_hotp_wrong_negative) {
    const char *K = "this is a secret";

    cotp_error_t err;
    char *hotp = get_hotp (K, -6, 8, COTP_SHA1, &err);

    cr_expect_eq (err, INVALID_COUNTER, "Expected %d to be equal to %d\n", err, INVALID_COUNTER);
    cr_assert_null (hotp);
}


Test(totp_generic, test_secret_with_space) {
    const char *K = "hxdm vjec jjws rb3h wizr 4ifu gftm xboz";
    const char *expected_totp = "488431";

    cotp_error_t err;
    char *totp = get_totp_at (K, 1506268800, 6, 30, COTP_SHA1, &err);
    cr_expect_str_eq (totp, expected_totp, "Expected %s to be equal to %s\n", totp, expected_totp);

    free (totp);
}


Test(totp_generic, test_fail_invalid_b32_input) {
    const char *K = "This input is not valid!";

    cotp_error_t err;
    char *totp = get_totp (K, 6, 30, COTP_SHA1, &err);

    cr_expect_eq (err, INVALID_B32_INPUT, "Expected %d to be equal to %d\n", err, INVALID_B32_INPUT);
    cr_assert_null (totp);
}


Test(totp_generic, test_fail_invalid_algo) {
    const char *K = "base32secret";

    int MD5 = 3;
    cotp_error_t err;
    char *totp = get_totp (K, 6, 30, MD5, &err);

    cr_expect_eq (err, INVALID_ALGO, "Expected %d to be equal to %d\n", err, INVALID_ALGO);
    cr_assert_null (totp);
}


Test(totp_generic, test_steam_totp) {
    const char *secret = "ON2XAZLSMR2XAZLSONSWG4TFOQ======";
    const char *expected_totp = "YRGQJ";
    long timestamp = 3000030;

    cotp_error_t err;
    char *totp = get_steam_totp_at (secret, timestamp, 30, &err);
    cr_expect_str_eq (totp, expected_totp, "Expected %s to be equal to %s\n", totp, expected_totp);

    free (totp);
}


Test(totp_generic, test_steam_totp_input_b64) {
    const char *b64_encoded_secret = "VGhpcyBpbnB1dCBpcyBub3QgdmFsaWQhCg==";

    cotp_error_t err;
    char *totp = get_steam_totp (b64_encoded_secret, 30, &err);
    cr_expect_null (totp, "Expected totp to be null");
    cr_expect_eq (err, INVALID_B32_INPUT, "Expected %d to be equal to %d\n", err, INVALID_B32_INPUT);
    cr_assert_null (totp);
}


Test(totp_rfc6238, test_60seconds) {
    const char *K = "12345678901234567890";
    const char *expected_totp = "360094";

    cotp_error_t cotp_err;
    char *secret_base32 = base32_encode ((const uint8_t *)K, strlen (K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (secret_base32, 1111111109, 6, 60, COTP_SHA1,  &err);
    cr_expect_str_eq (totp, expected_totp, "Expected %s to be equal to %s\n", totp, expected_totp);

    free (totp);
    free (secret_base32);
}


Test(totp_int, test_err_is_missing_zero) {
    const char *K = "12345678901234567890";
    const long counter = 1234567890;
    int64_t expected_totp = 689005924;

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp_str = get_totp_at (K_base32, counter, 10, 30, COTP_SHA1, &err);
    int64_t totp = otp_to_int (totp_str, &err);
    cr_expect_eq (err, MISSING_LEADING_ZERO, "Expected %d to be equal to %d\n", err, MISSING_LEADING_ZERO);

    free (totp_str);
    free (K_base32);
}


Test(totp_int, test_err_invalid_input) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    int64_t totp = otp_to_int ("124", &err);
    cr_expect_eq (err, INVALID_USER_INPUT, "Expected %d to be equal to %d\n", err, INVALID_USER_INPUT);
    cr_expect_eq (totp, -1, "Expected %ld to be equal to %d\n", totp, -1);

    free (K_base32);
}


Test(totp_int, test_err_invalid_characters) {
    cotp_error_t err;
    int64_t totp = otp_to_int ("12a4", &err);

    cr_expect_eq (err, INVALID_USER_INPUT, "Expected %d to be equal to %d\n", err, INVALID_USER_INPUT);
    cr_expect_eq (totp, -1, "Expected %ld to be equal to %d\n", totp, -1);
}


Test(totp_generic, test_null_secret) {
    cotp_error_t err;
    char *totp = get_totp (NULL, 6, 30, COTP_SHA1, &err);

    cr_expect_eq (err, INVALID_USER_INPUT, "Expected %d to be equal to %d\n", err, INVALID_USER_INPUT);
    cr_assert_null (totp);
}


Test(totp_generic, test_empty_secret) {
    cotp_error_t err;
    char *totp = get_totp ("", 6, 30, COTP_SHA1, &err);

    cr_expect_eq (err, EMPTY_STRING, "Expected %d to be equal to %d\n", err, EMPTY_STRING);
    cr_assert_null (totp);
}


Test(totp_boundary, test_min_digits) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 4, 30, COTP_SHA1, &err);
    cr_expect_eq (err, NO_ERROR, "Expected %d to be equal to %d\n", err, NO_ERROR);
    cr_assert_not_null (totp);
    cr_expect_eq (strlen(totp), 4, "Expected length 4, got %zu\n", strlen(totp));

    free (totp);
    free (K_base32);
}


Test(totp_boundary, test_max_digits) {
    const char *K = "12345678901234567890";
    const char *expected_totp = "0689005924";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 1234567890, 10, 30, COTP_SHA1, &err);
    cr_expect_eq (err, NO_ERROR, "Expected %d to be equal to %d\n", err, NO_ERROR);
    cr_assert_not_null (totp);
    cr_expect_eq (strlen(totp), 10, "Expected length 10, got %zu\n", strlen(totp));
    cr_expect_str_eq (totp, expected_totp, "Expected %s to be equal to %s\n", totp, expected_totp);

    free (totp);
    free (K_base32);
}


Test(totp_boundary, test_min_period) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 6, 1, COTP_SHA1, &err);
    cr_expect_eq (err, NO_ERROR, "Expected %d to be equal to %d\n", err, NO_ERROR);
    cr_assert_not_null (totp);

    free (totp);
    free (K_base32);
}


Test(totp_boundary, test_max_period) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 6, 120, COTP_SHA1, &err);
    cr_expect_eq (err, NO_ERROR, "Expected %d to be equal to %d\n", err, NO_ERROR);
    cr_assert_not_null (totp);

    free (totp);
    free (K_base32);
}


Test(totp_boundary, test_period_over_max) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 6, 121, COTP_SHA1, &err);
    cr_expect_eq (err, INVALID_PERIOD, "Expected %d to be equal to %d\n", err, INVALID_PERIOD);
    cr_assert_null (totp);

    free (K_base32);
}


Test(totp_boundary, test_digits_below_min) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 3, 30, COTP_SHA1, &err);
    cr_expect_eq (err, INVALID_DIGITS, "Expected %d to be equal to %d\n", err, INVALID_DIGITS);
    cr_assert_null (totp);

    free (K_base32);
}


Test(totp_boundary, test_digits_above_max) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 11, 30, COTP_SHA1, &err);
    cr_expect_eq (err, INVALID_DIGITS, "Expected %d to be equal to %d\n", err, INVALID_DIGITS);
    cr_assert_null (totp);

    free (K_base32);
}


// Context API tests (T2)
Test(ctx_api, test_create_valid) {
    cotp_ctx *ctx = cotp_ctx_create (6, 30, COTP_SHA1);
    cr_assert_not_null (ctx);
    cotp_ctx_free (ctx);
}


Test(ctx_api, test_create_all_algos) {
    cotp_ctx *ctx1 = cotp_ctx_create (6, 30, COTP_SHA1);
    cotp_ctx *ctx2 = cotp_ctx_create (6, 30, COTP_SHA256);
    cotp_ctx *ctx3 = cotp_ctx_create (6, 30, COTP_SHA512);
    cr_assert_not_null (ctx1);
    cr_assert_not_null (ctx2);
    cr_assert_not_null (ctx3);
    cotp_ctx_free (ctx1);
    cotp_ctx_free (ctx2);
    cotp_ctx_free (ctx3);
}


Test(ctx_api, test_create_invalid_digits) {
    cotp_ctx *ctx = cotp_ctx_create (3, 30, COTP_SHA1);
    cr_assert_null (ctx);

    ctx = cotp_ctx_create (11, 30, COTP_SHA1);
    cr_assert_null (ctx);
}


Test(ctx_api, test_create_invalid_period) {
    cotp_ctx *ctx = cotp_ctx_create (6, 0, COTP_SHA1);
    cr_assert_null (ctx);

    ctx = cotp_ctx_create (6, -1, COTP_SHA1);
    cr_assert_null (ctx);

    ctx = cotp_ctx_create (6, 121, COTP_SHA1);
    cr_assert_null (ctx);
}


Test(ctx_api, test_create_invalid_algo) {
    cotp_ctx *ctx = cotp_ctx_create (6, 30, 3);
    cr_assert_null (ctx);

    ctx = cotp_ctx_create (6, 30, -1);
    cr_assert_null (ctx);
}


Test(ctx_api, test_totp_at) {
    const char *K = "12345678901234567890";
    const char *expected_totp = "94287082";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_ctx *ctx = cotp_ctx_create (8, 30, COTP_SHA1);
    cr_assert_not_null (ctx);

    cotp_error_t err;
    char *totp = cotp_ctx_totp_at (ctx, K_base32, 59, &err);
    cr_expect_eq (err, NO_ERROR, "Expected %d to be equal to %d\n", err, NO_ERROR);
    cr_expect_str_eq (totp, expected_totp, "Expected %s to be equal to %s\n", totp, expected_totp);

    free (totp);
    cotp_ctx_free (ctx);
    free (K_base32);
}


Test(ctx_api, test_null_ctx) {
    cotp_error_t err;
    char *totp = cotp_ctx_totp_at (NULL, "secret", 59, &err);
    cr_expect_eq (err, INVALID_USER_INPUT, "Expected %d to be equal to %d\n", err, INVALID_USER_INPUT);
    cr_assert_null (totp);

    totp = cotp_ctx_totp (NULL, "secret", &err);
    cr_expect_eq (err, INVALID_USER_INPUT, "Expected %d to be equal to %d\n", err, INVALID_USER_INPUT);
    cr_assert_null (totp);
}


Test(ctx_api, test_free_null) {
    cotp_ctx_free (NULL);
}
