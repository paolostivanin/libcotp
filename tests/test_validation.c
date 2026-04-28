#include <criterion/criterion.h>
#include <string.h>
#include <limits.h>
#include "../src/cotp.h"

#ifdef COTP_ENABLE_VALIDATION

Test(validation, test_exact_match) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 8, 30, COTP_SHA1, &err);
    cr_assert_not_null (totp);

    int matched_delta = -999;
    int result = validate_totp_in_window (totp, K_base32, 59, 8, 30, COTP_SHA1, 1, &matched_delta, &err);
    cr_expect_eq (result, 1, "Expected match\n");
    cr_expect_eq (matched_delta, 0, "Expected delta 0, got %d\n", matched_delta);
    cr_expect_eq (err, VALID, "Expected VALID, got %d\n", err);

    free (totp);
    free (K_base32);
}


Test(validation, test_no_match) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    int matched_delta = -999;
    int result = validate_totp_in_window ("00000000", K_base32, 59, 8, 30, COTP_SHA1, 0, &matched_delta, &err);
    cr_expect_eq (result, 0, "Expected no match\n");

    free (K_base32);
}


Test(validation, test_window_offset_match) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    // Generate TOTP for timestamp 59
    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 8, 30, COTP_SHA1, &err);
    cr_assert_not_null (totp);

    // Validate at timestamp 59+30=89 (one period later) with window=1 should still match at delta=-1
    int matched_delta = -999;
    int result = validate_totp_in_window (totp, K_base32, 89, 8, 30, COTP_SHA1, 1, &matched_delta, &err);
    cr_expect_eq (result, 1, "Expected match within window\n");
    cr_expect_eq (matched_delta, -1, "Expected delta -1, got %d\n", matched_delta);

    free (totp);
    free (K_base32);
}


Test(validation, test_null_user_code) {
    cotp_error_t err;
    int result = validate_totp_in_window (NULL, "secret", 59, 8, 30, COTP_SHA1, 1, NULL, &err);
    cr_expect_eq (result, 0);
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(validation, test_null_secret) {
    cotp_error_t err;
    int result = validate_totp_in_window ("12345678", NULL, 59, 8, 30, COTP_SHA1, 1, NULL, &err);
    cr_expect_eq (result, 0);
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(validation, test_negative_window) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    cotp_error_t err;
    char *totp = get_totp_at (K_base32, 59, 8, 30, COTP_SHA1, &err);
    cr_assert_not_null (totp);

    // Negative window should be normalized to positive
    int matched_delta = -999;
    int result = validate_totp_in_window (totp, K_base32, 59, 8, 30, COTP_SHA1, -2, &matched_delta, &err);
    cr_expect_eq (result, 1, "Expected match with negative window\n");
    cr_expect_eq (matched_delta, 0, "Expected delta 0, got %d\n", matched_delta);

    free (totp);
    free (K_base32);
}


Test(validation, test_window_above_max_rejected) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    // window > 1024 must be rejected with INVALID_USER_INPUT
    cotp_error_t err = NO_ERROR;
    int result = validate_totp_in_window ("12345678", K_base32, 59, 8, 30, COTP_SHA1, 2000, NULL, &err);
    cr_expect_eq (result, 0);
    cr_expect_eq (err, INVALID_USER_INPUT);

    free (K_base32);
}


Test(validation, test_window_int_min_safe) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    // INT_MIN must not crash via -INT_MIN; should be clamped, then exceeding-max rejected
    cotp_error_t err = NO_ERROR;
    int result = validate_totp_in_window ("12345678", K_base32, 59, 8, 30, COTP_SHA1, INT_MIN, NULL, &err);
    cr_expect_eq (result, 0);
    // INT_MIN is normalized to MAX_WINDOW (1024) which is the boundary; either it runs through without finding a match (NO_ERROR) or hits the > MAX rejection — both are acceptable outcomes here, the assertion is "doesn't crash".

    free (K_base32);
}


Test(validation, test_overflow_guard_large_timestamp) {
    const char *K = "12345678901234567890";

    cotp_error_t cotp_err;
    char *K_base32 = base32_encode ((const uint8_t *)K, strlen(K)+1, &cotp_err);

    // timestamp near LONG_MAX with non-zero window: deltas whose addition would overflow
    // must be silently skipped (no UB, no crash). delta=0 still computes correctly so a
    // valid OTP at LONG_MAX should still match itself.
    cotp_error_t err = NO_ERROR;
    char *totp = get_totp_at (K_base32, LONG_MAX - 60, 8, 30, COTP_SHA1, &err);
    cr_assert_not_null (totp);
    cr_assert_eq (err, NO_ERROR);

    int matched_delta = -999;
    int result = validate_totp_in_window (totp, K_base32, LONG_MAX - 60, 8, 30, COTP_SHA1, 1024, &matched_delta, &err);
    cr_expect_eq (result, 1, "Expected delta=0 self-match even with overflowing positive deltas\n");
    cr_expect_eq (matched_delta, 0);

    free (totp);
    free (K_base32);
}

#endif // COTP_ENABLE_VALIDATION
