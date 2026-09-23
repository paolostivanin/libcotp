#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "pct.h"

static int
hex_val (char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

char *
cotp_pct_decode_n (const char *in, size_t len)
{
    if (in == NULL) return NULL;
    char *out = malloc (len + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (in[i] == '%') {
            // A '%' must be followed by two hex digits; a trailing '%' or a
            // truncated escape (e.g. "%4") is malformed, not literal input.
            if (i + 2 >= len) { free (out); return NULL; }
            int hi = hex_val (in[i+1]);
            int lo = hex_val (in[i+2]);
            if (hi < 0 || lo < 0) { free (out); return NULL; }
            unsigned char byte = (unsigned char)((hi << 4) | lo);
            if (byte == 0) { free (out); return NULL; }
            out[j++] = (char)byte;
            i += 2;
        } else {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
    return out;
}

char *
cotp_pct_encode (const char *in)
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
        if (unreserved) {
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
