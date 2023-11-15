#include <gcrypt.h>
#include "whmac.h"
#include "cotp.h"

typedef struct whmac_handle_s whmac_handle_t;

struct whmac_handle_s
{
    gcry_md_hd_t hd;
    int algo;
};

int gcrypt_algo[]=
{
    GCRY_MD_SHA1,
    GCRY_MD_SHA256,
    GCRY_MD_SHA512,
};

int
whmac_check (void)
{
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
        if (!gcry_check_version ("1.8.0")) {
            fprintf (stderr, "libgcrypt v1.8.0 and above is required\n");
            return -1;
        }
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    }
    return 0;
}

size_t
whmac_getlen (whmac_handle_t *hd)
{
    return gcry_md_get_algo_dlen(hd->algo);
}

whmac_handle_t *
whmac_gethandle (int algo)
{
    whmac_handle_t *whmac_handle = NULL;
    gcry_md_hd_t hd;
    if (algo >= sizeof(gcrypt_algo)/sizeof(int))
        return NULL;
    gpg_error_t gpg_err = gcry_md_open (&hd, gcrypt_algo[algo], GCRY_MD_FLAG_HMAC);
    if (gpg_err == 0) {
        whmac_handle = calloc(1, sizeof(*whmac_handle));
        memcpy(&whmac_handle->hd, &hd, sizeof(hd));
        whmac_handle->algo = gcrypt_algo[algo];
    }
    return whmac_handle;
}

void
whmac_freehandle (whmac_handle_t *hd)
{
    gcry_md_close (hd->hd);
    free(hd);
}

int
whmac_setkey (whmac_handle_t *hd,
                unsigned char * buffer,
                size_t buflen)
{
    if (gcry_md_setkey (hd->hd, buffer, buflen)) {
        return -INVALID_ALGO;
    }
    return NO_ERROR;
}

void
whmac_update (whmac_handle_t *hd,
                unsigned char * buffer,
                size_t buflen)
{
    gcry_md_write (hd->hd, buffer, buflen);
}

ssize_t
whmac_finalize(whmac_handle_t *hd,
                unsigned char * buffer,
                size_t buflen)
{
    ssize_t dlen = gcry_md_get_algo_dlen(hd->algo);
    if (buffer == NULL)
        return dlen;

    if (dlen > buflen) {
        return -MEMORY_ALLOCATION_ERROR;
    }

    gcry_md_final (hd->hd);

    unsigned char *hmac_tmp = gcry_md_read (hd->hd, hd->algo);
    if (hmac_tmp == NULL) {
        return -MEMORY_ALLOCATION_ERROR;
    }
    memcpy (buffer, hmac_tmp, dlen);
    return dlen;
}
