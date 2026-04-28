#include <stdlib.h>
#include <mbedtls/md.h>
#include "../whmac.h"
#include "../cotp.h"

typedef struct whmac_handle_s whmac_handle_t;

struct whmac_handle_s
{
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t *md_info;
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
    return mbedtls_md_get_size(hd->md_info);
}

whmac_handle_t *
whmac_gethandle (int algo)
{
    const mbedtls_md_type_t mbedtls_algo[] = {
        MBEDTLS_MD_SHA1,
        MBEDTLS_MD_SHA256,
        MBEDTLS_MD_SHA512,
    };

    if (algo < 0 || algo > 2) {
        return NULL;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type (mbedtls_algo[algo]);
    if (md_info == NULL) {
        return NULL;
    }

    whmac_handle_t *whmac_handle = calloc (1, sizeof(*whmac_handle));
    if (whmac_handle == NULL) {
        return NULL;
    }

    mbedtls_md_init (&(whmac_handle->sha_ctx));
    whmac_handle->md_info = md_info;
    int ret = mbedtls_md_setup (&(whmac_handle->sha_ctx), whmac_handle->md_info, 1);
    if (ret != 0) {
        mbedtls_md_free (&(whmac_handle->sha_ctx));
        free (whmac_handle);
        return NULL;
    }

    return whmac_handle;
}

void
whmac_freehandle (whmac_handle_t *hd)
{
    if (!hd) return;
    mbedtls_md_free (&(hd->sha_ctx));
    free (hd);
}

int
whmac_setkey (whmac_handle_t *hd,
              const unsigned char *buffer,
              size_t buflen)
{
    int ret = mbedtls_md_hmac_starts (&(hd->sha_ctx), buffer, buflen);
    if (ret != 0) {
        return WHMAC_ERROR;
    }
    return NO_ERROR;
}

int
whmac_update (whmac_handle_t *hd,
              const unsigned char *buffer,
              size_t buflen)
{
    if (hd == NULL) {
        return WHMAC_ERROR;
    }
    if (mbedtls_md_hmac_update (&(hd->sha_ctx), buffer, buflen) != 0) {
        return WHMAC_ERROR;
    }
    return NO_ERROR;
}

ssize_t
whmac_finalize (whmac_handle_t *hd,
                unsigned char *buffer,
                size_t buflen)
{
    if (hd == NULL || hd->md_info == NULL) {
        return -WHMAC_ERROR;
    }
    size_t dlen = mbedtls_md_get_size(hd->md_info);
    if (buffer == NULL) {
        return (ssize_t)dlen;
    }

    if (dlen > buflen) {
        return -MEMORY_ALLOCATION_ERROR;
    }

    if (mbedtls_md_hmac_finish (&(hd->sha_ctx), buffer) != 0) {
        return -WHMAC_ERROR;
    }

    return (ssize_t)dlen;
}
