#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "../cotp.h"
#include "secure_zero.h"

#ifdef COTP_ENABLE_VALIDATION

#define COTP_MAX_VALIDATION_WINDOW 1024

int validate_totp_in_window(const char* user_code,
                            const char* base32_encoded_secret,
                            long        timestamp,
                            int         digits,
                            int         period,
                            int         sha_algo,
                            int         window,
                            int*        matched_delta,
                            cotp_error_t* err_code)
{
    if (matched_delta) *matched_delta = 0;
    if (!user_code || !base32_encoded_secret) {
        if (err_code) *err_code = INVALID_USER_INPUT;
        return 0;
    }

    // Normalize window: handle INT_MIN safely (negation would overflow)
    if (window == INT_MIN) {
        window = COTP_MAX_VALIDATION_WINDOW;
    } else if (window < 0) {
        window = -window;
    }
    if (window > COTP_MAX_VALIDATION_WINDOW) {
        if (err_code) *err_code = INVALID_USER_INPUT;
        return 0;
    }

    size_t user_len = strlen(user_code);

    // Try [-window, +window]
    for (int delta = -window; delta <= window; ++delta) {
        long step;
        long t;
        if (__builtin_mul_overflow((long)delta, (long)period, &step) ||
            __builtin_add_overflow(timestamp, step, &t)) {
            // Skip deltas whose timestamp would overflow long
            continue;
        }
        cotp_error_t err = NO_ERROR;
        char* gen = get_totp_at(base32_encoded_secret, t, digits, period, sha_algo, &err);
        if (!gen) {
            if (err_code) *err_code = err;
            return 0;
        }
        size_t gen_len = strlen(gen);
        // Length check is fine non-constant-time: OTP length == digits is public.
        // When lengths match, do a timing-safe byte compare.
        int ok = 0;
        if (gen_len == user_len) {
            ok = (cotp_timing_safe_memcmp(gen, user_code, gen_len) == 0);
        }
        free(gen);
        if (ok) {
            if (matched_delta) *matched_delta = delta;
            if (err_code) *err_code = VALID;
            return 1;
        }
    }
    if (err_code) *err_code = NO_ERROR;
    return 0;
}

#endif // COTP_ENABLE_VALIDATION
