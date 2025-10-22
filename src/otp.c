#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
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

static char  *get_steam_code   (const uchar *hmac,
                                whmac_handle_t *hd);

static int    truncate         (const uchar *hmac,
                                int          digits_length,
                                whmac_handle_t *hd);

static uchar *compute_hmac     (const char  *K,
                                long         C,
                                whmac_handle_t *hd);

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
    if (whmac_check () == -1) {
        *err_code = WCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    if (check_algo (algo) == INVALID_ALGO) {
        *err_code = INVALID_ALGO;
        return NULL;
    }

    if (check_otp_len (digits) == INVALID_DIGITS) {
        *err_code = INVALID_DIGITS;
        return NULL;
    }

    if (counter < 0) {
        *err_code = INVALID_COUNTER;
        return NULL;
    }

    whmac_handle_t *hd = whmac_gethandle (algo);
    if (hd == NULL) {
        fprintf (stderr, "Error while opening the cipher handle.\n");
        return NULL;
    }

    unsigned char *hmac = compute_hmac (secret, counter, hd);
    if (hmac == NULL) {
        *err_code = WHMAC_ERROR;
        whmac_freehandle (hd);
        return NULL;
    }

    size_t dlen = whmac_getlen(hd);
    int tk = truncate (hmac, digits, hd);
    whmac_freehandle (hd);

    cotp_secure_memzero(hmac, dlen);
    free (hmac);

    *err_code = NO_ERROR;

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
    if (whmac_check () == -1) {
        *err_code = WCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    if (check_otp_len (digits) == INVALID_DIGITS) {
        *err_code = INVALID_DIGITS;
        return NULL;
    }

    if (check_period (period) == INVALID_PERIOD) {
        *err_code = INVALID_PERIOD;
        return NULL;
    }

    cotp_error_t err;
    char *totp = get_hotp (secret, current_timestamp / period, digits, algo, &err);
    if (err != NO_ERROR && err != VALID) {
        *err_code = err;
        return NULL;
    }
  
    *err_code = NO_ERROR;

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
    if (whmac_check () == -1) {
        *err_code = WCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    if (check_period (period) == INVALID_PERIOD) {
        *err_code = INVALID_PERIOD;
        return NULL;
    }

    whmac_handle_t *hd = whmac_gethandle (SHA1);
    if (hd == NULL) {
        fprintf (stderr, "Error while opening the cipher handle.\n");
        return NULL;
    }
    unsigned char *hmac = compute_hmac (secret, current_timestamp / period, hd);
    if (hmac == NULL) {
        *err_code = WHMAC_ERROR;
        whmac_freehandle (hd);
        return NULL;
    }

    char *totp = get_steam_code (hmac, hd);

    size_t dlen = whmac_getlen(hd);
    whmac_freehandle (hd);

    *err_code = NO_ERROR;

    cotp_secure_memzero(hmac, dlen);
    free(hmac);

    return totp;
}


int64_t
otp_to_int (const char   *otp,
            cotp_error_t *err_code)
{
    size_t len = strlen (otp);
    if (len < MIN_DIGTS || len > MAX_DIGITS) {
        *err_code = INVALID_USER_INPUT;
        return -1;
    }

    if (otp[0] == '0') {
        *err_code = MISSING_LEADING_ZERO;
    } else {
        *err_code = NO_ERROR;
    }

    return strtoll (otp, NULL, 10);
}


static char *
normalize_secret (const char *K)
{
    char *nK = calloc (strlen (K) + 1, 1);
    if (nK == NULL) {
        fprintf (stderr, "Error during memory allocation\n");
        return nK;
    }
    for (int i = 0, j = 0; K[i] != '\0'; i++) {
        if (K[i] != ' ') {
            nK[j++] = islower(K[i]) ? (char) toupper(K[i]) : K[i];
        }
    }
    return nK;
}


static char *
get_steam_code (const unsigned char *hmac,
                whmac_handle_t *hd)
{
    size_t hlen = whmac_getlen(hd);
    int offset = (hmac[hlen-1] & 0x0f);
    assert(hlen >= 4);
    assert(offset >= 0 && (size_t)offset + 3 < hlen);

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
truncate (const unsigned char *hmac,
          int            digits_length,
          whmac_handle_t *hd)
{
    // take the lower four bits of the last byte
    size_t hlen = whmac_getlen(hd);
    int offset = hmac[hlen - 1] & 0x0f;
    assert(hlen >= 4);
    assert(offset >= 0 && (size_t)offset + 3 < hlen);

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
              whmac_handle_t *hd)
{
    char *normalized_K = normalize_secret (K);
    if (normalized_K == NULL) {
        return NULL;
    }

    size_t secret_len = b32_decoded_len_from_str(normalized_K);

    cotp_error_t err;
    unsigned char *secret = base32_decode (normalized_K, strlen(normalized_K), &err);
    free (normalized_K);
    if (secret == NULL) {
        return NULL;
    }

    unsigned char C_reverse_byte_order[8];
    REVERSE_BYTES(C, C_reverse_byte_order);

    err = whmac_setkey (hd, secret, secret_len);
    if (err) {
        fprintf (stderr, "Error while setting the cipher key.\n");
        cotp_secure_memzero(secret, secret_len);
        free (secret);
        return NULL;
    }
    whmac_update (hd, C_reverse_byte_order, sizeof(C_reverse_byte_order));

    size_t dlen = whmac_getlen (hd);
    unsigned char *hmac = calloc (dlen, 1);
    if (hmac == NULL) {
        fprintf (stderr, "Error allocating memory");
        cotp_secure_memzero(secret, secret_len);
        free (secret);
        return NULL;
    }

    ssize_t flen = whmac_finalize (hd, hmac, dlen);
    if (flen < 0) {
        fprintf (stderr, "Error getting digest\n");
        cotp_secure_memzero(hmac, dlen);
        free (hmac);
        cotp_secure_memzero(secret, secret_len);
        free (secret);
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
    return (digits_length < MIN_DIGTS || digits_length > MAX_DIGITS) ? INVALID_DIGITS : VALID;
}


static int
check_algo (int algo)
{
    return (algo != SHA1 && algo != SHA256 && algo != SHA512) ? INVALID_ALGO : VALID;
}
