#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "whmac.h"
#include "cotp.h"

static char  *normalize_secret (const char  *K);

static char  *get_steam_code   (const uchar *hmac);

static int    truncate         (const uchar *hmac,
                                int          digits_length,
                                int          algo);

static uchar *compute_hmac     (const char  *K,
                                long         C,
                                int          algo);

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

    unsigned char *hmac = compute_hmac (secret, counter, algo);
    if (hmac == NULL) {
        *err_code = INVALID_B32_INPUT;
        return NULL;
    }

    int tk = truncate (hmac, digits, algo);
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

    long timestamp = current_timestamp / period;

    cotp_error_t err;
    char *totp = get_hotp (secret, timestamp, digits, algo, &err);
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

    long timestamp = current_timestamp / period;

    unsigned char *hmac = compute_hmac (secret, timestamp, SHA1);
    if (hmac == NULL) {
        *err_code = INVALID_B32_INPUT;
        return NULL;
    }

    char *totp = get_steam_code (hmac);

    *err_code = NO_ERROR;

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
get_steam_code (const unsigned char *hmac)
{
    int offset = (hmac[whmac_getlen(SHA1)-1] & 0x0f);

    // Starting from the offset, take the successive 4 bytes while stripping the topmost bit to prevent it being handled as a signed integer
    int bin_code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | ((hmac[offset + 3] & 0xff));

    const char steam_alphabet[] = "23456789BCDFGHJKMNPQRTVWXY";

    char code[6];
    size_t steam_alphabet_len = strlen (steam_alphabet);
    for (int i = 0; i < 5; i++) {
        int mod = (int)(bin_code % steam_alphabet_len);
        bin_code = (int)(bin_code / steam_alphabet_len);
        code[i] = steam_alphabet[mod];
    }
    code[5] = '\0';

    return strdup(code);
}


static int
truncate (const unsigned char *hmac,
          int            digits_length,
          int            algo)
{
    // take the lower four bits of the last byte
    int offset = hmac[whmac_getlen(algo) - 1] & 0x0f;

    // Starting from the offset, take the successive 4 bytes while stripping the topmost bit to prevent it being handled as a signed integer
    int bin_code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | ((hmac[offset + 3] & 0xff));

    long long int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 10000000000};
    int token = (int)(bin_code % DIGITS_POWER[digits_length]);

    return token;
}


static unsigned char *
compute_hmac (const char *K,
              long        C,
              int         algo)
{
    size_t secret_len = (size_t)((strlen(K) + 1.6 - 1) / 1.6);

    char *normalized_K = normalize_secret (K);
    if (normalized_K == NULL) {
        return NULL;
    }

    cotp_error_t err;
    unsigned char *secret = base32_decode (normalized_K, strlen(normalized_K), &err);
    free (normalized_K);
    if (secret == NULL) {
        return NULL;
    }

    unsigned char C_reverse_byte_order[8];
    int j, i;
    for (j = 0, i = 7; j < 8 && i >= 0; j++, i--) {
        C_reverse_byte_order[i] = ((unsigned char *) &C)[j];
    }

    whmac_handle_t *hd = whmac_gethandle(algo);
    if (hd == NULL) {
        fprintf (stderr, "Error while opening the cipher handle.\n");
        free (secret);
        return NULL;
    }
    cotp_error_t copterr = whmac_setkey(hd, secret, secret_len);
    if (copterr) {
        fprintf (stderr, "Error while setting the cipher key.\n");
        free (secret);
        whmac_freehandle (hd);
        return NULL;
    }
    whmac_update (hd, C_reverse_byte_order, sizeof (C_reverse_byte_order));

    size_t dlen = whmac_getlen(algo);
    unsigned char *hmac = malloc (dlen);
    if (hmac == NULL) {
        fprintf (stderr, "Error allocating memory");
        free (secret);
        whmac_freehandle (hd);
        return NULL;
    }

    ssize_t flen = whmac_finalize (hd, hmac, dlen);
    if (flen < 0) {
        fprintf (stderr, "Error getting digest\n");
        free (secret);
        whmac_freehandle (hd);
        return NULL;
    }
    free (secret);

    whmac_freehandle (hd);

    return hmac;
}


static char *
finalize (int digits_length,
          int tk)
{
    char *token = calloc (digits_length + 1, 1);
    if (!token) return token;
    char fmt[6];
    sprintf (fmt, "%%0%dd", digits_length);
    snprintf (token, digits_length + 1, fmt, tk);
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
