#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include "../cotp.h"
#include "secure_zero.h"
#include "pct.h"

#define OTPAUTH_PREFIX     "otpauth://"
#define OTPAUTH_PREFIX_LEN 10

// Reusable validation matching otp.c's check_* helpers.
static int validate_algo (int algo)   { return (algo == COTP_SHA1 || algo == COTP_SHA256 || algo == COTP_SHA512); }
static int validate_digits (int d)    { return (d >= MIN_DIGITS && d <= MAX_DIGITS); }
static int validate_period (int p)    { return (p > 0 && p <= 120); }

// A secret made only of ASCII spaces (or empty) would later be normalized to an
// empty string by the generators; reject it at the URI boundary instead.
static int secret_is_blank (const char *s) {
    if (!s) return 1;
    for (; *s; s++) {
        if (*s != ' ') return 0;
    }
    return 1;
}

static int parse_int (const char *s, size_t len, long *out) {
    if (len == 0 || len > 30) return 0;
    char buf[32];
    memcpy (buf, s, len);
    buf[len] = '\0';
    char *end = NULL;
    errno = 0;
    long v = strtol (buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') return 0;
    *out = v;
    return 1;
}

void
cotp_otpauth_uri_free (cotp_otpauth_uri *u)
{
    if (!u) return;
    if (u->secret) {
        cotp_secure_memzero (u->secret, strlen (u->secret));
        free (u->secret);
    }
    free (u->issuer);
    free (u->account);
    free (u);
}

cotp_otpauth_uri *
cotp_otpauth_uri_parse (const char *uri, cotp_error_t *err)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err ? err : &local_err;

    if (uri == NULL || strncmp (uri, OTPAUTH_PREFIX, OTPAUTH_PREFIX_LEN) != 0) {
        *errp = INVALID_USER_INPUT;
        return NULL;
    }

    const char *p = uri + OTPAUTH_PREFIX_LEN;

    // Type
    const char *slash = strchr (p, '/');
    if (!slash) { *errp = INVALID_USER_INPUT; return NULL; }
    size_t type_len = (size_t)(slash - p);
    cotp_otpauth_type type;
    if (type_len == 4 && strncasecmp (p, "totp", 4) == 0) {
        type = COTP_OTPAUTH_TOTP;
    } else if (type_len == 4 && strncasecmp (p, "hotp", 4) == 0) {
        type = COTP_OTPAUTH_HOTP;
    } else {
        *errp = INVALID_USER_INPUT;
        return NULL;
    }
    p = slash + 1;

    // Label up to '?'
    const char *qmark = strchr (p, '?');
    size_t label_len = qmark ? (size_t)(qmark - p) : strlen (p);

    char *label_issuer_raw = NULL;
    char *label_account_raw = NULL;
    if (label_len > 0) {
        const char *colon = memchr (p, ':', label_len);
        if (colon) {
            size_t issuer_len = (size_t)(colon - p);
            size_t account_len = label_len - issuer_len - 1;
            label_issuer_raw  = cotp_pct_decode_n (p, issuer_len);
            label_account_raw = cotp_pct_decode_n (colon + 1, account_len);
            if (!label_issuer_raw || !label_account_raw) {
                free (label_issuer_raw);
                free (label_account_raw);
                *errp = INVALID_USER_INPUT;
                return NULL;
            }
            // An empty label issuer (":account") must not shadow &issuer=.
            if (label_issuer_raw[0] == '\0') {
                free (label_issuer_raw);
                label_issuer_raw = NULL;
            }
        } else {
            label_account_raw = cotp_pct_decode_n (p, label_len);
            if (!label_account_raw) { *errp = INVALID_USER_INPUT; return NULL; }
        }
    }

    cotp_otpauth_uri *u = calloc (1, sizeof (*u));
    if (!u) {
        free (label_issuer_raw);
        free (label_account_raw);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }
    u->type    = type;
    u->issuer  = label_issuer_raw;
    u->account = label_account_raw;
    u->algo    = COTP_SHA1;
    u->digits  = 6;
    u->period  = 30;
    u->counter = 0;

    int saw_secret  = 0;
    int saw_counter = 0;

    // Query string
    if (qmark) {
        const char *qp = qmark + 1;
        while (*qp) {
            const char *amp = strchr (qp, '&');
            size_t seg_len = amp ? (size_t)(amp - qp) : strlen (qp);
            const char *eq = memchr (qp, '=', seg_len);
            if (!eq) {
                // Segment without '=': skip it, but keep parsing the rest.
                if (!amp) break;
                qp = amp + 1;
                continue;
            }
            size_t key_len = (size_t)(eq - qp);
            const char *val = eq + 1;
            size_t val_len = seg_len - key_len - 1;

            if (key_len == 6 && strncasecmp (qp, "secret", 6) == 0) {
                if (u->secret) {
                    cotp_secure_memzero (u->secret, strlen (u->secret));
                    free (u->secret);
                }
                u->secret = cotp_pct_decode_n (val, val_len);
                if (!u->secret) { cotp_otpauth_uri_free (u); *errp = INVALID_USER_INPUT; return NULL; }
                saw_secret = 1;
            } else if (key_len == 6 && strncasecmp (qp, "issuer", 6) == 0) {
                if (!u->issuer) {
                    u->issuer = cotp_pct_decode_n (val, val_len);
                    if (!u->issuer) { cotp_otpauth_uri_free (u); *errp = INVALID_USER_INPUT; return NULL; }
                }
            } else if (key_len == 9 && strncasecmp (qp, "algorithm", 9) == 0) {
                if (val_len == 4 && strncasecmp (val, "SHA1", 4) == 0)        u->algo = COTP_SHA1;
                else if (val_len == 6 && strncasecmp (val, "SHA256", 6) == 0) u->algo = COTP_SHA256;
                else if (val_len == 6 && strncasecmp (val, "SHA512", 6) == 0) u->algo = COTP_SHA512;
                else { cotp_otpauth_uri_free (u); *errp = INVALID_ALGO; return NULL; }
            } else if (key_len == 6 && strncasecmp (qp, "digits", 6) == 0) {
                long v;
                if (!parse_int (val, val_len, &v) || v < INT_MIN || v > INT_MAX) {
                    cotp_otpauth_uri_free (u); *errp = INVALID_DIGITS; return NULL;
                }
                u->digits = (int)v;
            } else if (key_len == 6 && strncasecmp (qp, "period", 6) == 0) {
                long v;
                if (!parse_int (val, val_len, &v) || v < INT_MIN || v > INT_MAX) {
                    cotp_otpauth_uri_free (u); *errp = INVALID_PERIOD; return NULL;
                }
                u->period = (int)v;
            } else if (key_len == 7 && strncasecmp (qp, "counter", 7) == 0) {
                long v;
                if (!parse_int (val, val_len, &v)) {
                    cotp_otpauth_uri_free (u); *errp = INVALID_COUNTER; return NULL;
                }
                u->counter = v;
                saw_counter = 1;
            }
            // Unknown keys silently ignored.

            if (!amp) break;
            qp = amp + 1;
        }
    }

    // Final validation
    if (!saw_secret || secret_is_blank (u->secret)) {
        cotp_otpauth_uri_free (u);
        *errp = INVALID_USER_INPUT;
        return NULL;
    }
    if (!is_string_valid_b32 (u->secret)) {
        cotp_otpauth_uri_free (u);
        *errp = INVALID_B32_INPUT;
        return NULL;
    }
    if (!validate_algo (u->algo))   { cotp_otpauth_uri_free (u); *errp = INVALID_ALGO;   return NULL; }
    if (!validate_digits (u->digits)) { cotp_otpauth_uri_free (u); *errp = INVALID_DIGITS; return NULL; }
    if (u->type == COTP_OTPAUTH_TOTP && !validate_period (u->period)) {
        cotp_otpauth_uri_free (u); *errp = INVALID_PERIOD; return NULL;
    }
    if (u->type == COTP_OTPAUTH_HOTP) {
        if (!saw_counter) { cotp_otpauth_uri_free (u); *errp = INVALID_COUNTER; return NULL; }
        if (u->counter < 0) { cotp_otpauth_uri_free (u); *errp = INVALID_COUNTER; return NULL; }
    }

    *errp = NO_ERROR;
    return u;
}

char *
cotp_otpauth_uri_build (const cotp_otpauth_uri *u, cotp_error_t *err)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err ? err : &local_err;

    if (!u || secret_is_blank (u->secret))                                         { *errp = INVALID_USER_INPUT; return NULL; }
    if (u->type != COTP_OTPAUTH_TOTP && u->type != COTP_OTPAUTH_HOTP)               { *errp = INVALID_USER_INPUT; return NULL; }
    if (!is_string_valid_b32 (u->secret))                                           { *errp = INVALID_B32_INPUT;  return NULL; }
    if (!validate_algo (u->algo))                                                   { *errp = INVALID_ALGO;       return NULL; }
    if (!validate_digits (u->digits))                                               { *errp = INVALID_DIGITS;     return NULL; }
    if (u->type == COTP_OTPAUTH_TOTP && !validate_period (u->period))               { *errp = INVALID_PERIOD;     return NULL; }
    if (u->type == COTP_OTPAUTH_HOTP && u->counter < 0)                             { *errp = INVALID_COUNTER;    return NULL; }

    const char *type_str = (u->type == COTP_OTPAUTH_TOTP) ? "totp" : "hotp";
    const char *algo_str = (u->algo == COTP_SHA256) ? "SHA256"
                          : (u->algo == COTP_SHA512) ? "SHA512" : "SHA1";

    // Encode each label component; the ':' separator between issuer and account is added literally below.
    // Same encoded string is reused for both the label-form ("Issuer:Account") and the &issuer= query param.
    char *enc_issuer        = u->issuer  ? cotp_pct_encode (u->issuer)  : NULL;
    char *enc_account_label = u->account ? cotp_pct_encode (u->account) : NULL;
    char *enc_secret        = cotp_pct_encode (u->secret);

    if (!enc_secret || (u->issuer && !enc_issuer) || (u->account && !enc_account_label)) {
        free (enc_issuer); free (enc_account_label); free (enc_secret);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    // Two-pass snprintf: measure, then format.
    // Format: otpauth://TYPE/[ISSUER:]ACCOUNT?secret=...&algorithm=...&digits=...&[period|counter]=...&[issuer=...]
    int n;
    if (u->type == COTP_OTPAUTH_TOTP) {
        n = snprintf (NULL, 0, "otpauth://%s/%s%s%s?secret=%s&algorithm=%s&digits=%d&period=%d%s%s",
                      type_str,
                      enc_issuer ? enc_issuer : "",
                      enc_issuer ? ":" : "",
                      enc_account_label ? enc_account_label : "",
                      enc_secret, algo_str, u->digits, u->period,
                      enc_issuer ? "&issuer=" : "",
                      enc_issuer ? enc_issuer : "");
    } else {
        n = snprintf (NULL, 0, "otpauth://%s/%s%s%s?secret=%s&algorithm=%s&digits=%d&counter=%ld%s%s",
                      type_str,
                      enc_issuer ? enc_issuer : "",
                      enc_issuer ? ":" : "",
                      enc_account_label ? enc_account_label : "",
                      enc_secret, algo_str, u->digits, u->counter,
                      enc_issuer ? "&issuer=" : "",
                      enc_issuer ? enc_issuer : "");
    }
    if (n < 0) {
        free (enc_issuer); free (enc_account_label); free (enc_secret);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    char *out = malloc ((size_t)n + 1);
    if (!out) {
        free (enc_issuer); free (enc_account_label); free (enc_secret);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    if (u->type == COTP_OTPAUTH_TOTP) {
        snprintf (out, (size_t)n + 1, "otpauth://%s/%s%s%s?secret=%s&algorithm=%s&digits=%d&period=%d%s%s",
                  type_str,
                  enc_issuer ? enc_issuer : "",
                  enc_issuer ? ":" : "",
                  enc_account_label ? enc_account_label : "",
                  enc_secret, algo_str, u->digits, u->period,
                  enc_issuer ? "&issuer=" : "",
                  enc_issuer ? enc_issuer : "");
    } else {
        snprintf (out, (size_t)n + 1, "otpauth://%s/%s%s%s?secret=%s&algorithm=%s&digits=%d&counter=%ld%s%s",
                  type_str,
                  enc_issuer ? enc_issuer : "",
                  enc_issuer ? ":" : "",
                  enc_account_label ? enc_account_label : "",
                  enc_secret, algo_str, u->digits, u->counter,
                  enc_issuer ? "&issuer=" : "",
                  enc_issuer ? enc_issuer : "");
    }

    free (enc_issuer);
    free (enc_account_label);
    free (enc_secret);

    *errp = NO_ERROR;
    return out;
}
