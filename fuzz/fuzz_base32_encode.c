#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cotp.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {
    if (size > 4096) return 0;

    cotp_error_t err;
    char *encoded = base32_encode (data, size, &err);
    if (encoded) {
        // Exercise the decoder (and encode again) on our own output.
        uint8_t *decoded = base32_decode (encoded, strlen (encoded), &err);
        free (decoded);

        char *reencoded = base32_encode ((const uint8_t *)encoded, strlen (encoded), &err);
        free (reencoded);
    }
    free (encoded);

    // Also exercise the "caller includes the trailing NUL in data_len" path.
    char *with_nul = malloc (size + 1);
    if (!with_nul) return 0;
    memcpy (with_nul, data, size);
    with_nul[size] = '\0';

    char *encoded2 = base32_encode ((const uint8_t *)with_nul, size + 1, &err);
    free (encoded2);
    free (with_nul);
    return 0;
}
