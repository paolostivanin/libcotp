#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cotp.h"

// Layout of input bytes:
//   [0]      algo selector (% 3)  -> COTP_SHA1 / COTP_SHA256 / COTP_SHA512
//   [1]      digits (% 7 + 4)     -> 4..10
//   [2]      period (% 120 + 1)   -> 1..120
//   [3..10]  timestamp (long, host-endian via memcpy)
//   [11..]   secret (NUL-terminated copy)
int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {
    if (size < 11 || size > 4096) return 0;

    int algo   = data[0] % 3;
    int digits = (data[1] % 7) + 4;
    int period = (data[2] % 120) + 1;

    long ts;
    memcpy (&ts, data + 3, sizeof (ts));

    size_t secret_len = size - 11;
    char *secret = malloc (secret_len + 1);
    if (!secret) return 0;
    memcpy (secret, data + 11, secret_len);
    secret[secret_len] = '\0';

    cotp_error_t err;
    char *otp = get_totp_at (secret, ts, digits, period, algo, &err);
    free (otp);

    char *hotp = get_hotp (secret, ts < 0 ? 0 : ts, digits, algo, &err);
    free (hotp);

    free (secret);
    return 0;
}
