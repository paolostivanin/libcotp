#include <string.h>
#include "../cotp.h"

#ifdef COTP_ENABLE_VALIDATION

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

    // Normalize window
    if (window < 0) window = -window;

    // Try [-window, +window]
    for (int delta = -window; delta <= window; ++delta) {
        long t = timestamp + (long)delta * (long)period;
        cotp_error_t err = NO_ERROR;
        char* gen = get_totp_at(base32_encoded_secret, t, digits, period, sha_algo, &err);
        if (!gen) {
            if (err_code) *err_code = err;
            return 0;
        }
        int ok = (strcmp(gen, user_code) == 0);
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
