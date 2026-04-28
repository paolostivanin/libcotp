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
    uint8_t *out = base32_decode (s, size + 1, &err);
    free (out);

    // Also exercise the no-trailing-NUL path
    out = base32_decode (s, size, &err);
    free (out);

    free (s);
    return 0;
}
