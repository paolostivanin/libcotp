#include <criterion/criterion.h>
#include <string.h>
#include "../src/cotp.h"

Test(strerror, every_enum_value_has_message) {
    const cotp_error_t codes[] = {
        NO_ERROR,
        VALID,
        WCRYPT_VERSION_MISMATCH,
        INVALID_B32_INPUT,
        INVALID_ALGO,
        INVALID_DIGITS,
        INVALID_PERIOD,
        MEMORY_ALLOCATION_ERROR,
        INVALID_USER_INPUT,
        EMPTY_STRING,
        MISSING_LEADING_ZERO,
        INVALID_COUNTER,
        WHMAC_ERROR,
    };
    const size_t n = sizeof(codes) / sizeof(codes[0]);
    for (size_t i = 0; i < n; i++) {
        const char *s = cotp_strerror (codes[i]);
        cr_assert_not_null (s, "cotp_strerror(%d) returned NULL\n", codes[i]);
        cr_expect_gt (strlen (s), 0, "cotp_strerror(%d) returned empty string\n", codes[i]);
    }
}


Test(strerror, unknown_value_returns_unknown) {
    const char *s = cotp_strerror ((cotp_error_t)99999);
    cr_assert_not_null (s);
    cr_expect_str_eq (s, "unknown error");
}


Test(strerror, no_error_message) {
    cr_expect_str_eq (cotp_strerror (NO_ERROR), "no error");
}
