#include <criterion/criterion.h>
#include <string.h>
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

#endif // COTP_ENABLE_VALIDATION
