#include <mbedtls/md.h>
#include "../whash.h"

int
whash_sha256 (const unsigned char *data,
              size_t               len,
              unsigned char        out[32])
{
    if (out == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type (MBEDTLS_MD_SHA256);
    if (info == NULL) {
        return -1;
    }
    if (mbedtls_md (info, data, len, out) != 0) {
        return -1;
    }
    return 0;
}
