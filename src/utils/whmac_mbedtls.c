#include <stdio.h>
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
    const mbedtls_md_type_t openssl_algo[] = {
        MBEDTLS_MD_SHA1,
        MBEDTLS_MD_SHA256,
        MBEDTLS_MD_SHA512,
    };

    whmac_handle_t *whmac_handle = calloc (1, sizeof(*whmac_handle));
    if (whmac_handle == NULL) {
        return NULL;
    }

    if (algo > 2) {
        free (whmac_handle);
        return NULL;
    }
    
    mbedtls_md_init (&(whmac_handle->sha_ctx));
    whmac_handle->md_info = mbedtls_md_info_from_type (openssl_algo[algo]);
    int ret = mbedtls_md_setup (&(whmac_handle->sha_ctx), whmac_handle->md_info, 1);
    if (ret != 0) {
        printf ("mbedtls_md_setup() returned -0x%04x\n", -ret);
        mbedtls_md_free (&(whmac_handle->sha_ctx));
        free (whmac_handle);
        return NULL;
    }

    return whmac_handle;
}

void
whmac_freehandle (whmac_handle_t *hd)
{
    mbedtls_md_free (&(hd->sha_ctx));
    free (hd);
}

int
whmac_setkey (whmac_handle_t *hd,
              unsigned char *buffer,
              size_t buflen)
{
    mbedtls_md_hmac_starts (&(hd->sha_ctx), buffer, buflen);
    return NO_ERROR;
}

void
whmac_update (whmac_handle_t *hd,
              unsigned char *buffer,
              size_t buflen)
{   
    mbedtls_md_hmac_update (&(hd->sha_ctx), buffer, buflen);
}

ssize_t
whmac_finalize (whmac_handle_t *hd,
                unsigned char *buffer,
                size_t buflen)
{
    mbedtls_md_hmac_finish (&(hd->sha_ctx), buffer);

    return buflen;
}

