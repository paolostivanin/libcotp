#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include "../cotp.h"
#include "secure_zero.h"
#include "pct.h"

#define YAOTP_URI_PREFIX     "otpauth://yaotp/"
#define YAOTP_URI_PREFIX_LEN 16

// Cap opaque pass-through fields (track_id, uid) at 128 decoded bytes each. The Yandex format
// keeps these short (UUID-like); refusing oversized values prevents URI-bomb-style allocations.
#define YAOTP_OPAQUE_MAX     128

static int
parse_int (const char *s, size_t len, long *out)
{
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
cotp_yaotp_uri_free (cotp_yaotp_uri *u)
{
    if (!u) return;
    if (u->secret) {
        cotp_secure_memzero (u->secret, strlen (u->secret));
        free (u->secret);
    }
    free (u->account);
    free (u->issuer);
    free (u->track_id);
    free (u->uid);
    free (u);
}

cotp_yaotp_uri *
cotp_yaotp_uri_parse (const char *uri, cotp_error_t *err)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err ? err : &local_err;

    if (uri == NULL || strncasecmp (uri, YAOTP_URI_PREFIX, YAOTP_URI_PREFIX_LEN) != 0) {
        *errp = INVALID_USER_INPUT;
        return NULL;
    }

    const char *p = uri + YAOTP_URI_PREFIX_LEN;

    // Label up to '?'. Account from label takes precedence over "&name=" query param.
    const char *qmark = strchr (p, '?');
    size_t label_len = qmark ? (size_t)(qmark - p) : strlen (p);

    char *label_account_raw = NULL;
    if (label_len > 0) {
        label_account_raw = cotp_pct_decode_n (p, label_len);
        if (!label_account_raw) { *errp = INVALID_USER_INPUT; return NULL; }
    }

    cotp_yaotp_uri *u = calloc (1, sizeof (*u));
    if (!u) {
        free (label_account_raw);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }
    u->account    = label_account_raw;
    u->pin_length = -1;

    int saw_pin_length = 0;

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
                u->secret = cotp_pct_decode_n (val, val_len);
                if (!u->secret) { cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL; }
            } else if (key_len == 6 && strncasecmp (qp, "issuer", 6) == 0) {
                free (u->issuer);
                u->issuer = cotp_pct_decode_n (val, val_len);
                if (!u->issuer) { cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL; }
            } else if (key_len == 4 && strncasecmp (qp, "name", 4) == 0) {
                // Only set from query if the label didn't already provide an account.
                if (!u->account) {
                    u->account = cotp_pct_decode_n (val, val_len);
                    if (!u->account) { cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL; }
                }
            } else if (key_len == 10 && strncasecmp (qp, "pin_length", 10) == 0) {
                long v;
                if (!parse_int (val, val_len, &v) || v < INT_MIN || v > INT_MAX) {
                    cotp_yaotp_uri_free (u); *errp = INVALID_YAOTP_PIN; return NULL;
                }
                u->pin_length = (int)v;
                saw_pin_length = 1;
            } else if (key_len == 8 && strncasecmp (qp, "track_id", 8) == 0) {
                if (val_len > YAOTP_OPAQUE_MAX * 3) {
                    cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL;
                }
                free (u->track_id);
                u->track_id = cotp_pct_decode_n (val, val_len);
                if (!u->track_id) { cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL; }
                if (strlen (u->track_id) > YAOTP_OPAQUE_MAX) {
                    cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL;
                }
            } else if (key_len == 3 && strncasecmp (qp, "uid", 3) == 0) {
                if (val_len > YAOTP_OPAQUE_MAX * 3) {
                    cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL;
                }
                free (u->uid);
                u->uid = cotp_pct_decode_n (val, val_len);
                if (!u->uid) { cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL; }
                if (strlen (u->uid) > YAOTP_OPAQUE_MAX) {
                    cotp_yaotp_uri_free (u); *errp = INVALID_USER_INPUT; return NULL;
                }
            }
            // Unknown keys silently ignored, matching cotp_otpauth_uri_parse's behavior.

            if (!amp) break;
            qp = amp + 1;
        }
    }

    if (!u->secret || u->secret[0] == '\0') {
        cotp_yaotp_uri_free (u);
        *errp = INVALID_USER_INPUT;
        return NULL;
    }
    if (!is_string_valid_b32 (u->secret)) {
        cotp_yaotp_uri_free (u);
        *errp = INVALID_B32_INPUT;
        return NULL;
    }
    if (!saw_pin_length ||
        u->pin_length < COTP_YAOTP_MIN_PIN_LENGTH ||
        u->pin_length > COTP_YAOTP_MAX_PIN_LENGTH) {
        cotp_yaotp_uri_free (u);
        *errp = INVALID_YAOTP_PIN;
        return NULL;
    }

    *errp = NO_ERROR;
    return u;
}

char *
cotp_yaotp_uri_build (const cotp_yaotp_uri *u, cotp_error_t *err)
{
    cotp_error_t local_err = NO_ERROR;
    cotp_error_t *errp = err ? err : &local_err;

    if (!u || !u->secret || u->secret[0] == '\0') { *errp = INVALID_USER_INPUT; return NULL; }
    if (!is_string_valid_b32 (u->secret))         { *errp = INVALID_B32_INPUT;  return NULL; }
    if (u->pin_length < COTP_YAOTP_MIN_PIN_LENGTH ||
        u->pin_length > COTP_YAOTP_MAX_PIN_LENGTH) {
        *errp = INVALID_YAOTP_PIN;
        return NULL;
    }

    char *enc_account  = u->account  ? cotp_pct_encode (u->account)  : NULL;
    char *enc_secret   = cotp_pct_encode (u->secret);
    char *enc_issuer   = u->issuer   ? cotp_pct_encode (u->issuer)   : NULL;
    char *enc_track_id = u->track_id ? cotp_pct_encode (u->track_id) : NULL;
    char *enc_uid      = u->uid      ? cotp_pct_encode (u->uid)      : NULL;

    if (!enc_secret ||
        (u->account  && !enc_account)  ||
        (u->issuer   && !enc_issuer)   ||
        (u->track_id && !enc_track_id) ||
        (u->uid      && !enc_uid)) {
        free (enc_account); free (enc_secret); free (enc_issuer);
        free (enc_track_id); free (enc_uid);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    // Format: otpauth://yaotp/[ACCOUNT]?secret=...&pin_length=N[&issuer=...][&track_id=...][&uid=...]
    // Literal format strings inline to satisfy -Wformat-nonliteral while keeping optional fields conditional.
    int n = snprintf (NULL, 0, "otpauth://yaotp/%s?secret=%s&pin_length=%d%s%s%s%s%s%s",
                      enc_account ? enc_account : "",
                      enc_secret, u->pin_length,
                      enc_issuer   ? "&issuer="   : "", enc_issuer   ? enc_issuer   : "",
                      enc_track_id ? "&track_id=" : "", enc_track_id ? enc_track_id : "",
                      enc_uid      ? "&uid="      : "", enc_uid      ? enc_uid      : "");
    if (n < 0) {
        free (enc_account); free (enc_secret); free (enc_issuer);
        free (enc_track_id); free (enc_uid);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    char *out = malloc ((size_t)n + 1);
    if (!out) {
        free (enc_account); free (enc_secret); free (enc_issuer);
        free (enc_track_id); free (enc_uid);
        *errp = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    snprintf (out, (size_t)n + 1, "otpauth://yaotp/%s?secret=%s&pin_length=%d%s%s%s%s%s%s",
              enc_account ? enc_account : "",
              enc_secret, u->pin_length,
              enc_issuer   ? "&issuer="   : "", enc_issuer   ? enc_issuer   : "",
              enc_track_id ? "&track_id=" : "", enc_track_id ? enc_track_id : "",
              enc_uid      ? "&uid="      : "", enc_uid      ? enc_uid      : "");

    free (enc_account); free (enc_secret); free (enc_issuer);
    free (enc_track_id); free (enc_uid);

    *errp = NO_ERROR;
    return out;
}
