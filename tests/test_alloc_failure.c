#include <criterion/criterion.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "../src/cotp.h"

// H2 regression: finalize() can fail to allocate the result buffer. The callers
// must report MEMORY_ALLOCATION_ERROR instead of NULL + NO_ERROR.
//
// The library sources are compiled directly into this test and linked with
// -Wl,--wrap=calloc, so calloc() calls made by the library can be made to fail
// deterministically. We target the specific allocation finalize() performs:
// calloc(digits + 1, 1). With digits=7 that is (8,1), which none of the other
// allocations on these code paths use for the chosen secret.

static int    fail_nmemb = -1;
static size_t fail_size  = 0;

void *__real_calloc (size_t nmemb, size_t size);

void *__wrap_calloc (size_t nmemb, size_t size) {
    if (fail_nmemb >= 0 && (size_t)fail_nmemb == nmemb && fail_size == size) {
        return NULL;
    }
    return __real_calloc (nmemb, size);
}

// 16 base32 chars -> 10 decoded bytes -> calloc(11, 1); normalize -> calloc(17, 1).
static const char *kSecret = "JBSWY3DPEHPK3PXP";

static void arm_finalize_oom (void) { fail_nmemb = 8; fail_size = 1; }
static void disarm (void)           { fail_nmemb = -1; }

Test(alloc_failure, hotp_finalize_oom) {
    arm_finalize_oom();
    cotp_error_t err = NO_ERROR;
    char *otp = get_hotp (kSecret, 0, 7, COTP_SHA1, &err);
    disarm();

    cr_expect_null (otp);
    cr_expect_eq (err, MEMORY_ALLOCATION_ERROR);
}

Test(alloc_failure, totp_finalize_oom) {
    arm_finalize_oom();
    cotp_error_t err = NO_ERROR;
    char *otp = get_totp_at (kSecret, 59, 7, 30, COTP_SHA1, &err);
    disarm();

    cr_expect_null (otp);
    cr_expect_eq (err, MEMORY_ALLOCATION_ERROR);
}

#ifdef COTP_ENABLE_VALIDATION
Test(alloc_failure, validation_finalize_oom) {
    arm_finalize_oom();
    cotp_error_t err = NO_ERROR;
    int matched_delta = -1;
    int result = validate_totp_in_window ("0000000", kSecret, 59, 7, 30,
                                          COTP_SHA1, 0, &matched_delta, &err);
    disarm();

    cr_expect_eq (result, 0);
    cr_expect_eq (err, MEMORY_ALLOCATION_ERROR);
}
#endif

// Control: with the interposer disarmed the same call succeeds, so a failure
// above can only come from the injected allocation failure.
Test(alloc_failure, success_path_not_affected) {
    cotp_error_t err = NO_ERROR;
    char *otp = get_hotp (kSecret, 0, 7, COTP_SHA1, &err);

    cr_assert_not_null (otp);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_eq (strlen (otp), 7);
    free (otp);
}
