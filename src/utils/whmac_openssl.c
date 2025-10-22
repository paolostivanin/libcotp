#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "../whmac.h"
#include "../cotp.h"

typedef struct whmac_handle_s whmac_handle_t;

struct whmac_handle_s
{
    EVP_MAC *mac;
    OSSL_PARAM mac_params[4];
    EVP_MAC_CTX *ctx;
    int algo;
    size_t dlen;
};

int
whmac_check (void)
{
    return 0;
}

size_t
whmac_getlen (whmac_handle_t *hd)
{
    return hd->dlen;
}

whmac_handle_t *
whmac_gethandle (int algo)
{
    const char *openssl_algo[] = {
        "SHA1",
        "SHA256",
        "SHA512",
    };

    whmac_handle_t *whmac_handle = NULL;
    if (algo > 2) {
        return NULL;
    }

    EVP_MAC *mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
    if (mac != NULL) {
        whmac_handle = calloc (1, sizeof(*whmac_handle));
        if (whmac_handle == NULL) {
            return NULL;
        }
        whmac_handle->mac = mac;
        whmac_handle->algo = algo;

        size_t params_n = 0;

        whmac_handle->mac_params[params_n++] = OSSL_PARAM_construct_utf8_string ("digest", (char *)openssl_algo[algo], 0);
        whmac_handle->mac_params[params_n] = OSSL_PARAM_construct_end ();
    }
    return whmac_handle;
}

void
whmac_freehandle (whmac_handle_t *hd)
{
    EVP_MAC_free (hd->mac);
    free (hd);
}

int
whmac_setkey (whmac_handle_t *hd,
              const unsigned char  *buffer,
              size_t          buflen)
{
    hd->ctx = EVP_MAC_CTX_new (hd->mac);
    if (hd->ctx && !EVP_MAC_init (hd->ctx, buffer, buflen, hd->mac_params)) {
        ERR_print_errors_fp (stderr);
        return -INVALID_ALGO;
    }
    hd->dlen = EVP_MAC_CTX_get_mac_size (hd->ctx);
    return NO_ERROR;
}

void
whmac_update (whmac_handle_t *hd,
              const unsigned char  *buffer,
              size_t          buflen)
{
    EVP_MAC_update (hd->ctx, buffer, buflen);
}

ssize_t
whmac_finalize(whmac_handle_t *hd,
               unsigned char  *buffer,
               size_t          buflen)
{
    size_t dlen = EVP_MAC_CTX_get_mac_size (hd->ctx);
    if (buffer == NULL) {
        return dlen;
    }

    if (dlen > buflen) {
        return -MEMORY_ALLOCATION_ERROR;
    }

    EVP_MAC_final (hd->ctx, buffer, &dlen, buflen);
    EVP_MAC_CTX_free (hd->ctx);
    hd->ctx = NULL;

    return dlen;
}
