#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cotp.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {
    if (size > 4096) return 0;
    char *s = malloc (size + 1);
    if (!s) return 0;
    memcpy (s, data, size);
    s[size] = '\0';

    cotp_error_t err;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (s, &err);
    if (u) {
        // Round-trip: build back, then parse again — should not crash.
        char *rebuilt = cotp_otpauth_uri_build (u, &err);
        if (rebuilt) {
            cotp_otpauth_uri *u2 = cotp_otpauth_uri_parse (rebuilt, &err);
            cotp_otpauth_uri_free (u2);
            free (rebuilt);
        }
        cotp_otpauth_uri_free (u);
    }

    free (s);
    return 0;
}
