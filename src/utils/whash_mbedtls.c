#include <mbedtls/sha256.h>
#include "../whash.h"

int
whash_sha256 (const unsigned char *data,
              size_t               len,
              unsigned char        out[32])
{
    if (out == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    if (mbedtls_sha256 (data, len, out, 0) != 0) {
        return -1;
    }
    return 0;
}
