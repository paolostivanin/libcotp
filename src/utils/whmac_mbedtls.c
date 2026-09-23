#include <stdlib.h>
#include <sys/types.h>   /* ssize_t */

/* Portable MbedTLS version detection: 2.x predates <mbedtls/build_info.h>. */
#if defined(__has_include)
#  if __has_include(<mbedtls/build_info.h>)
#    include <mbedtls/build_info.h>
#  else
#    include <mbedtls/version.h>
#  endif
#else
#  include <mbedtls/version.h>
#endif

#include "../whmac.h"
#include "../cotp.h"

typedef struct whmac_handle_s whmac_handle_t;

#if MBEDTLS_VERSION_MAJOR >= 4

/* ---------------------------------------------------------------------------
 * MbedTLS 4.x demoted the classic mbedtls_md_hmac_* API to private identifiers
 * (PSA is the public HMAC path now). Implement the wrapper on PSA Crypto.
 * ------------------------------------------------------------------------- */
#include <psa/crypto.h>

struct whmac_handle_s
{
    psa_mac_operation_t  op;    /* zero-initialised == PSA_MAC_OPERATION_INIT */
    mbedtls_svc_key_id_t key;   /* zero-initialised == PSA_KEY_ID_NULL        */
    psa_algorithm_t      alg;   /* PSA_ALG_HMAC(hash)                         */
    size_t               dlen;
    int                  algo;
    int                  op_active;
    int                  key_set;
};

static const psa_algorithm_t psa_hash_algo[] = {
    PSA_ALG_SHA_1,
    PSA_ALG_SHA_256,
    PSA_ALG_SHA_512,
};

int
whmac_check (void)
{
    /* psa_crypto_init() is idempotent; safe to call before every computation. */
    return (psa_crypto_init () == PSA_SUCCESS) ? 0 : -1;
}

size_t
whmac_getlen (whmac_handle_t *hd)
{
    return hd->dlen;
}

whmac_handle_t *
whmac_gethandle (int algo)
{
    if (algo < 0 || algo > 2) {
        return NULL;
    }

    /* calloc yields {0}, which matches PSA_MAC_OPERATION_INIT and PSA_KEY_ID_NULL. */
    whmac_handle_t *whmac_handle = calloc (1, sizeof (*whmac_handle));
    if (whmac_handle == NULL) {
        return NULL;
    }

    whmac_handle->algo = algo;
    whmac_handle->alg  = PSA_ALG_HMAC (psa_hash_algo[algo]);
    whmac_handle->dlen = PSA_HASH_LENGTH (psa_hash_algo[algo]);

    return whmac_handle;
}

void
whmac_freehandle (whmac_handle_t *hd)
{
    if (!hd) return;
    if (hd->op_active) {
        psa_mac_abort (&(hd->op));
    }
    if (hd->key_set) {
        psa_destroy_key (hd->key);
    }
    free (hd);
}

int
whmac_setkey (whmac_handle_t      *hd,
              const unsigned char *buffer,
              size_t               buflen)
{
    if (hd == NULL) {
        return WHMAC_ERROR;
    }

    psa_key_attributes_t attributes = psa_key_attributes_init ();
    psa_set_key_usage_flags (&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm (&attributes, hd->alg);
    psa_set_key_type (&attributes, PSA_KEY_TYPE_HMAC);

    psa_status_t status = psa_import_key (&attributes, buffer, buflen, &(hd->key));
    psa_reset_key_attributes (&attributes);
    if (status != PSA_SUCCESS) {
        return WHMAC_ERROR;
    }
    hd->key_set = 1;

    if (psa_mac_sign_setup (&(hd->op), hd->key, hd->alg) != PSA_SUCCESS) {
        psa_destroy_key (hd->key);
        hd->key_set = 0;
        return WHMAC_ERROR;
    }
    hd->op_active = 1;

    return NO_ERROR;
}

int
whmac_update (whmac_handle_t      *hd,
              const unsigned char *buffer,
              size_t               buflen)
{
    if (hd == NULL || !hd->op_active) {
        return WHMAC_ERROR;
    }
    if (psa_mac_update (&(hd->op), buffer, buflen) != PSA_SUCCESS) {
        return WHMAC_ERROR;
    }
    return NO_ERROR;
}

ssize_t
whmac_finalize (whmac_handle_t *hd,
                unsigned char  *buffer,
                size_t          buflen)
{
    if (hd == NULL) {
        return -WHMAC_ERROR;
    }
    if (buffer == NULL) {
        /* Length probe: report the digest size without consuming the operation. */
        return (ssize_t) hd->dlen;
    }
    if (hd->dlen > buflen) {
        return -MEMORY_ALLOCATION_ERROR;
    }

    size_t out_len = 0;
    psa_status_t status = psa_mac_sign_finish (&(hd->op), buffer, buflen, &out_len);
    if (status != PSA_SUCCESS) {
        /* PSA requires an explicit abort to release an operation that errored. */
        psa_mac_abort (&(hd->op));
    }
    hd->op_active = 0;
    if (hd->key_set) {
        psa_destroy_key (hd->key);
        hd->key_set = 0;
    }
    if (status != PSA_SUCCESS) {
        return -WHMAC_ERROR;
    }

    return (ssize_t) out_len;
}

#else  /* MBEDTLS_VERSION_MAJOR < 4 */

/* ---------------------------------------------------------------------------
 * MbedTLS 2.x / 3.x: the classic mbedtls_md_hmac_* generic-hash API.
 * ------------------------------------------------------------------------- */
#include <mbedtls/md.h>

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
    if (hd == NULL) {
        return WHMAC_ERROR;
    }
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

#endif /* MBEDTLS_VERSION_MAJOR */
