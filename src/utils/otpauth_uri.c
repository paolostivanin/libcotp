#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include "../cotp.h"
#include "secure_zero.h"

#define OTPAUTH_PREFIX     "otpauth://"
#define OTPAUTH_PREFIX_LEN 10

static int hex_val (char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Percent-decode a buffer of given length. Returns malloc'd NUL-terminated string, or NULL on OOM/invalid escape.
static char *
pct_decode_n (const char *in, size_t len)
{
    char *out = malloc (len + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (in[i] == '%' && i + 2 < len) {
            int hi = hex_val (in[i+1]);
            int lo = hex_val (in[i+2]);
            if (hi < 0 || lo < 0) { free (out); return NULL; }
            out[j++] = (char)((hi << 4) | lo);
            i += 2;
        } else {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
    return out;
}

// Percent-encode for unreserved set per RFC 3986 (plus ':' kept readable in label).
// `keep_colon` allows ':' to remain unescaped (for the label "Issuer:Account" form).
static char *
pct_encode (const char *in, int keep_colon)
{
    static const char hex[] = "0123456789ABCDEF";
    if (!in) return NULL;
    size_t len = strlen (in);
    char *out = malloc (len * 3 + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        int unreserved = (isalnum (c) || c == '-' || c == '_' || c == '.' || c == '~');
        if (unreserved || (keep_colon && c == ':')) {
            out[j++] = (char)c;
        } else {
            out[j++] = '%';
            out[j++] = hex[c >> 4];
            out[j++] = hex[c & 0x0F];
        }
    }
    out[j] = '\0';
    return out;
}

// Reusable validation matching otp.c's check_* helpers.
static int validate_algo (int algo)   { return (algo == COTP_SHA1 || algo == COTP_SHA256 || algo == COTP_SHA512); }
static int validate_digits (int d)    { return (d >= MIN_DIGITS && d <= MAX_DIGITS); }
static int validate_period (int p)    { return (p > 0 && p <= 120); }

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
            label_issuer_raw  = pct_decode_n (p, issuer_len);
            label_account_raw = pct_decode_n (colon + 1, account_len);
            if (!label_issuer_raw || !label_account_raw) {
                free (label_issuer_raw);
                free (label_account_raw);
                *errp = MEMORY_ALLOCATION_ERROR;
                return NULL;
            }
        } else {
            label_account_raw = pct_decode_n (p, label_len);
            if (!label_account_raw) { *errp = MEMORY_ALLOCATION_ERROR; return NULL; }
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
            const char *eq = strchr (qp, '=');
            if (!eq) break;
            size_t key_len = (size_t)(eq - qp);
            const char *val = eq + 1;
            const char *amp = strchr (val, '&');
            size_t val_len = amp ? (size_t)(amp - val) : strlen (val);

            if (key_len == 6 && strncasecmp (qp, "secret", 6) == 0) {
                free (u->secret);
                u->secret = pct_decode_n (val, val_len);
                if (!u->secret) { cotp_otpauth_uri_free (u); *errp = MEMORY_ALLOCATION_ERROR; return NULL; }
                saw_secret = 1;
            } else if (key_len == 6 && strncasecmp (qp, "issuer", 6) == 0) {
                if (!u->issuer) {
                    u->issuer = pct_decode_n (val, val_len);
                    if (!u->issuer) { cotp_otpauth_uri_free (u); *errp = MEMORY_ALLOCATION_ERROR; return NULL; }
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
    if (!saw_secret || !u->secret || u->secret[0] == '\0') {
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

    if (!u || !u->secret || u->secret[0] == '\0')                                   { *errp = INVALID_USER_INPUT; return NULL; }
    if (u->type != COTP_OTPAUTH_TOTP && u->type != COTP_OTPAUTH_HOTP)               { *errp = INVALID_USER_INPUT; return NULL; }
    if (!is_string_valid_b32 (u->secret))                                           { *errp = INVALID_B32_INPUT;  return NULL; }
    if (!validate_algo (u->algo))                                                   { *errp = INVALID_ALGO;       return NULL; }
    if (!validate_digits (u->digits))                                               { *errp = INVALID_DIGITS;     return NULL; }
    if (u->type == COTP_OTPAUTH_TOTP && !validate_period (u->period))               { *errp = INVALID_PERIOD;     return NULL; }
    if (u->type == COTP_OTPAUTH_HOTP && u->counter < 0)                             { *errp = INVALID_COUNTER;    return NULL; }

    const char *type_str = (u->type == COTP_OTPAUTH_TOTP) ? "totp" : "hotp";
    const char *algo_str = (u->algo == COTP_SHA256) ? "SHA256"
                          : (u->algo == COTP_SHA512) ? "SHA512" : "SHA1";

    // Encode parts. Label keeps ':' readable so that "Issuer:Account" is human-friendly.
    char *enc_issuer_label  = u->issuer  ? pct_encode (u->issuer,  0) : NULL;
    char *enc_account_label = u->account ? pct_encode (u->account, 0) : NULL;
    char *enc_secret        = pct_encode (u->secret, 0);
    char *enc_issuer_query  = u->issuer  ? pct_encode (u->issuer,  0) : NULL;

    if (!enc_secret || (u->issuer && (!enc_issuer_label || !enc_issuer_query)) ||
        (u->account && !enc_account_label)) {
        free (enc_issuer_label); free (enc_account_label); free (enc_secret); free (enc_issuer_query);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    // Two-pass snprintf: measure, then format.
    // Format: otpauth://TYPE/[ISSUER:]ACCOUNT?secret=...&algorithm=...&digits=...&[period|counter]=...&[issuer=...]
    int n;
    if (u->type == COTP_OTPAUTH_TOTP) {
        n = snprintf (NULL, 0, "otpauth://%s/%s%s%s?secret=%s&algorithm=%s&digits=%d&period=%d%s%s",
                      type_str,
                      enc_issuer_label ? enc_issuer_label : "",
                      enc_issuer_label ? ":" : "",
                      enc_account_label ? enc_account_label : "",
                      enc_secret, algo_str, u->digits, u->period,
                      enc_issuer_query ? "&issuer=" : "",
                      enc_issuer_query ? enc_issuer_query : "");
    } else {
        n = snprintf (NULL, 0, "otpauth://%s/%s%s%s?secret=%s&algorithm=%s&digits=%d&counter=%ld%s%s",
                      type_str,
                      enc_issuer_label ? enc_issuer_label : "",
                      enc_issuer_label ? ":" : "",
                      enc_account_label ? enc_account_label : "",
                      enc_secret, algo_str, u->digits, u->counter,
                      enc_issuer_query ? "&issuer=" : "",
                      enc_issuer_query ? enc_issuer_query : "");
    }
    if (n < 0) {
        free (enc_issuer_label); free (enc_account_label); free (enc_secret); free (enc_issuer_query);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    char *out = malloc ((size_t)n + 1);
    if (!out) {
        free (enc_issuer_label); free (enc_account_label); free (enc_secret); free (enc_issuer_query);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    if (u->type == COTP_OTPAUTH_TOTP) {
        snprintf (out, (size_t)n + 1, "otpauth://%s/%s%s%s?secret=%s&algorithm=%s&digits=%d&period=%d%s%s",
                  type_str,
                  enc_issuer_label ? enc_issuer_label : "",
                  enc_issuer_label ? ":" : "",
                  enc_account_label ? enc_account_label : "",
                  enc_secret, algo_str, u->digits, u->period,
                  enc_issuer_query ? "&issuer=" : "",
                  enc_issuer_query ? enc_issuer_query : "");
    } else {
        snprintf (out, (size_t)n + 1, "otpauth://%s/%s%s%s?secret=%s&algorithm=%s&digits=%d&counter=%ld%s%s",
                  type_str,
                  enc_issuer_label ? enc_issuer_label : "",
                  enc_issuer_label ? ":" : "",
                  enc_account_label ? enc_account_label : "",
                  enc_secret, algo_str, u->digits, u->counter,
                  enc_issuer_query ? "&issuer=" : "",
                  enc_issuer_query ? enc_issuer_query : "");
    }

    free (enc_issuer_label);
    free (enc_account_label);
    free (enc_secret);
    free (enc_issuer_query);

    *errp = NO_ERROR;
    return out;
}
