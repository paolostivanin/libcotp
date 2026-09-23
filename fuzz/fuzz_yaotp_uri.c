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
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (s, &err);
    if (u) {
        // Round-trip: build back, then parse again — should not crash.
        char *rebuilt = cotp_yaotp_uri_build (u, &err);
        if (rebuilt) {
            cotp_yaotp_uri *u2 = cotp_yaotp_uri_parse (rebuilt, &err);
            cotp_yaotp_uri_free (u2);
            free (rebuilt);
        }
        // Exercise the generator boundary with the parsed secret.
        if (u->pin_length >= COTP_YAOTP_MIN_PIN_LENGTH &&
            u->pin_length <= COTP_YAOTP_MAX_PIN_LENGTH) {
            char pin[COTP_YAOTP_MAX_PIN_LENGTH + 1];
            for (int i = 0; i < u->pin_length; i++) pin[i] = '0';
            pin[u->pin_length] = '\0';
            char *code = get_yaotp_at (u->secret, pin, 1581064020L, &err);
            free (code);
        }
        cotp_yaotp_uri_free (u);
    }

    // Also drive the generator with the raw input as a candidate secret.
    char *code = get_yaotp_at (s, "0000", 1581064020L, &err);
    free (code);

    free (s);
    return 0;
}
