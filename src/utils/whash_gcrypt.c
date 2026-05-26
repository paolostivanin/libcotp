#include <gcrypt.h>
#include "../whash.h"

int
whash_sha256 (const unsigned char *data,
              size_t               len,
              unsigned char        out[32])
{
    if (out == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    gcry_md_hash_buffer (GCRY_MD_SHA256, out, data, len);
    return 0;
}
