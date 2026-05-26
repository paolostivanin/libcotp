#include <openssl/evp.h>
#include "../whash.h"

int
whash_sha256 (const unsigned char *data,
              size_t               len,
              unsigned char        out[32])
{
    if (out == NULL || (data == NULL && len > 0)) {
        return -1;
    }
    unsigned int md_len = 32;
    if (EVP_Digest (data, len, out, &md_len, EVP_sha256 (), NULL) != 1) {
        return -1;
    }
    if (md_len != 32) {
        return -1;
    }
    return 0;
}
