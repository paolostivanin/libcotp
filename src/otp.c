#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include "whmac.h"
#include "cotp.h"
#include "utils/secure_zero.h"

static size_t b32_decoded_len_from_str(const char *s) {
    if (!s) return 0;
    size_t chars = 0;
    for (const char *p = s; *p; ++p) {
        if (*p != '=' && *p != ' ') {
            ++chars;
        }
    }
    return (chars * 5) / 8; // floor
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define REVERSE_BYTES(C, C_reverse_byte_order)           \
        for (int j = 0, i = 7; j < 8; j++, i--) {            \
            (C_reverse_byte_order)[i] = ((unsigned char *)&(C))[j]; \
        }
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define REVERSE_BYTES(C, C_reverse_byte_order)           \
        for (int j = 0; j < 8; j++) {                        \
            (C_reverse_byte_order)[j] = ((unsigned char *)&(C))[j]; \
        }
#else
    #error "Unknown endianness"
#endif

static char  *normalize_secret (const char  *K);

static char  *get_steam_code   (const unsigned char *hmac,
                                whmac_handle_t *hd);

static int    truncate_otp     (const unsigned char *hmac,
                                int          digits_length,
                                whmac_handle_t *hd);

static unsigned char *compute_hmac (const char  *K,
                                long         C,
                                whmac_handle_t *hd,
                                cotp_error_t *err_code);

static char  *finalize         (int          digits_length,
                                int          tk);

static int    check_period     (int          period);

static int    check_otp_len    (int          digits_length);

static int    check_algo       (int          algo);


char *
get_hotp (const char   *secret,
          long          counter,
          int           digits,
          int           algo,
          cotp_error_t *err_code)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err_code ? err_code : &local_err;

    if (secret == NULL) {
        *errp = INVALID_USER_INPUT;
        return NULL;
    }

    if (whmac_check () == -1) {
        *errp = WCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    if (check_algo (algo) == INVALID_ALGO) {
        *errp = INVALID_ALGO;
        return NULL;
    }

    if (check_otp_len (digits) == INVALID_DIGITS) {
        *errp = INVALID_DIGITS;
        return NULL;
    }

    if (counter < 0) {
        *errp = INVALID_COUNTER;
        return NULL;
    }

    whmac_handle_t *hd = whmac_gethandle (algo);
    if (hd == NULL) {
        *errp = WHMAC_ERROR;
        return NULL;
    }

    unsigned char *hmac = compute_hmac (secret, counter, hd, errp);
    if (hmac == NULL) {
        whmac_freehandle (hd);
        return NULL;
    }

    size_t dlen = whmac_getlen(hd);
    int tk = truncate_otp (hmac, digits, hd);
    whmac_freehandle (hd);

    cotp_secure_memzero(hmac, dlen);
    free (hmac);

    if (tk == INT_MIN) {
        *errp = WHMAC_ERROR;
        return NULL;
    }

    *errp = NO_ERROR;

    return finalize (digits, tk);
}


char *
get_totp_at (const char   *secret,
             long          current_timestamp,
             int           digits,
             int           period,
             int           algo,
             cotp_error_t *err_code)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err_code ? err_code : &local_err;

    if (secret == NULL) {
        *errp = INVALID_USER_INPUT;
        return NULL;
    }

    if (whmac_check () == -1) {
        *errp = WCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    if (check_otp_len (digits) == INVALID_DIGITS) {
        *errp = INVALID_DIGITS;
        return NULL;
    }

    if (check_period (period) == INVALID_PERIOD) {
        *errp = INVALID_PERIOD;
        return NULL;
    }

    cotp_error_t err;
    char *totp = get_hotp (secret, current_timestamp / period, digits, algo, &err);
    if (err != NO_ERROR && err != VALID) {
        *errp = err;
        return NULL;
    }

    *errp = NO_ERROR;

    return totp;
}


char *
get_totp (const char   *secret,
          int           digits,
          int           period,
          int           algo,
          cotp_error_t *err_code)
{
    return get_totp_at (secret, (long)time(NULL), digits, period, algo, err_code);
}


char *
get_steam_totp (const char   *secret,
                int           period,
                cotp_error_t *err_code)
{
    // AFAIK, the secret is stored base64 encoded on the device. As I don't have time to waste on reverse engineering
    // this non-standard solution, the user is responsible for decoding the secret in whatever format this is and then
    // providing the library with the secret base32 encoded.
    return get_steam_totp_at (secret, (long)time(NULL), period, err_code);
}


char *
get_steam_totp_at (const char   *secret,
                   long          current_timestamp,
                   int           period,
                   cotp_error_t *err_code)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err_code ? err_code : &local_err;

    if (secret == NULL) {
        *errp = INVALID_USER_INPUT;
        return NULL;
    }

    if (whmac_check () == -1) {
        *errp = WCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    if (check_period (period) == INVALID_PERIOD) {
        *errp = INVALID_PERIOD;
        return NULL;
    }

    whmac_handle_t *hd = whmac_gethandle (COTP_SHA1);
    if (hd == NULL) {
        *errp = WHMAC_ERROR;
        return NULL;
    }
    unsigned char *hmac = compute_hmac (secret, current_timestamp / period, hd, errp);
    if (hmac == NULL) {
        whmac_freehandle (hd);
        return NULL;
    }

    char *totp = get_steam_code (hmac, hd);

    size_t dlen = whmac_getlen(hd);
    whmac_freehandle (hd);

    if (totp == NULL) {
        *errp = WHMAC_ERROR;
    } else {
        *errp = NO_ERROR;
    }

    cotp_secure_memzero(hmac, dlen);
    free(hmac);

    return totp;
}


int64_t
otp_to_int (const char   *otp,
            cotp_error_t *err_code)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err_code ? err_code : &local_err;

    if (otp == NULL) {
        *errp = INVALID_USER_INPUT;
        return -1;
    }

    size_t len = strlen (otp);
    if (len < MIN_DIGITS || len > MAX_DIGITS) {
        *errp = INVALID_USER_INPUT;
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)otp[i])) {
            *errp = INVALID_USER_INPUT;
            return -1;
        }
    }

    if (otp[0] == '0') {
        *errp = MISSING_LEADING_ZERO;
    } else {
        *errp = NO_ERROR;
    }

    return strtoll (otp, NULL, 10);
}


static char *
normalize_secret (const char *K)
{
    char *nK = calloc (strlen (K) + 1, 1);
    if (nK == NULL) {
        return nK;
    }
    for (int i = 0, j = 0; K[i] != '\0'; i++) {
        if (K[i] != ' ') {
            nK[j++] = islower((unsigned char)K[i]) ? (char) toupper((unsigned char)K[i]) : K[i];
        }
    }
    return nK;
}


static char *
get_steam_code (const unsigned char *hmac,
                whmac_handle_t *hd)
{
    size_t hlen = whmac_getlen(hd);
    if (hlen < 4) {
        return NULL;
    }
    int offset = (hmac[hlen-1] & 0x0f);
    if ((size_t)offset + 3 >= hlen) {
        return NULL;
    }

    // Starting from the offset, take the successive 4 bytes while stripping the topmost bit to prevent it being handled as a signed integer
    uint32_t bin_code = ((uint32_t)(hmac[offset] & 0x7f) << 24) | ((uint32_t)(hmac[offset + 1] & 0xff) << 16) | ((uint32_t)(hmac[offset + 2] & 0xff) << 8) | ((uint32_t)(hmac[offset + 3] & 0xff));

    const char steam_alphabet[] = "23456789BCDFGHJKMNPQRTVWXY";

    char code[6];
    size_t steam_alphabet_len = strlen (steam_alphabet);
    for (int i = 0; i < 5; i++) {
        uint32_t mod = bin_code % (uint32_t)steam_alphabet_len;
        bin_code = bin_code / (uint32_t)steam_alphabet_len;
        code[i] = steam_alphabet[mod];
    }
    code[5] = '\0';

    return strdup (code);
}


static int
truncate_otp (const unsigned char *hmac,
              int            digits_length,
              whmac_handle_t *hd)
{
    // take the lower four bits of the last byte
    size_t hlen = whmac_getlen(hd);
    if (hlen < 4) {
        return INT_MIN;
    }
    int offset = hmac[hlen - 1] & 0x0f;
    if ((size_t)offset + 3 >= hlen) {
        return INT_MIN;
    }

    // Starting from the offset, take the successive 4 bytes while stripping the topmost bit to prevent it being handled as a signed integer
    uint32_t bin_code = ((uint32_t)(hmac[offset] & 0x7f) << 24) | ((uint32_t)(hmac[offset + 1] & 0xff) << 16) | ((uint32_t)(hmac[offset + 2] & 0xff) << 8) | ((uint32_t)(hmac[offset + 3] & 0xff));

    uint64_t mod = 1;
    for (int i = 0; i < digits_length; ++i) {
        mod *= 10ULL;
    }
    int token = (int)(((uint64_t)bin_code) % mod);

    return token;
}


static unsigned char *
compute_hmac (const char *K,
              long        C,
              whmac_handle_t *hd,
              cotp_error_t *err_code)
{
    if (err_code == NULL) {
        return NULL;
    }

    if (K == NULL) {
        *err_code = INVALID_USER_INPUT;
        return NULL;
    }

    char *normalized_K = normalize_secret (K);
    if (normalized_K == NULL) {
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    if (normalized_K[0] == '\0') {
        free(normalized_K);
        *err_code = EMPTY_STRING;
        return NULL;
    }

    size_t secret_len = b32_decoded_len_from_str(normalized_K);

    unsigned char *secret = base32_decode (normalized_K, strlen(normalized_K), err_code);
    free (normalized_K);
    if (secret == NULL) {
        return NULL;
    }
    if (*err_code != NO_ERROR) {
        cotp_secure_memzero(secret, secret_len);
        free(secret);
        return NULL;
    }

    unsigned char C_reverse_byte_order[8];
    REVERSE_BYTES(C, C_reverse_byte_order);

    cotp_error_t err = whmac_setkey (hd, secret, secret_len);
    if (err) {
        cotp_secure_memzero(secret, secret_len);
        free (secret);
        *err_code = WHMAC_ERROR;
        return NULL;
    }
    whmac_update (hd, C_reverse_byte_order, sizeof(C_reverse_byte_order));

    size_t dlen = whmac_getlen (hd);
    unsigned char *hmac = calloc (dlen, 1);
    if (hmac == NULL) {
        cotp_secure_memzero(secret, secret_len);
        free (secret);
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    ssize_t flen = whmac_finalize (hd, hmac, dlen);
    if (flen < 0) {
        cotp_secure_memzero(hmac, dlen);
        free (hmac);
        cotp_secure_memzero(secret, secret_len);
        free (secret);
        *err_code = WHMAC_ERROR;
        return NULL;
    }
    cotp_secure_memzero(secret, secret_len);
    free (secret);

    return hmac;
}


static char *
finalize (int digits_length,
          int tk)
{
    char *token = calloc (digits_length + 1, 1);
    if (token == NULL) {
        return NULL;
    }
    // Print with leading zeros without building an intermediate format string
    snprintf (token, digits_length + 1, "%0*d", digits_length, tk);
    return token;
}


static int
check_period (int period)
{
    return (period <= 0 || period > 120) ? INVALID_PERIOD : VALID;
}


static int
check_otp_len (int digits_length)
{
    return (digits_length < MIN_DIGITS || digits_length > MAX_DIGITS) ? INVALID_DIGITS : VALID;
}


static int
check_algo (int algo)
{
    return (algo != COTP_SHA1 && algo != COTP_SHA256 && algo != COTP_SHA512) ? INVALID_ALGO : VALID;
}
