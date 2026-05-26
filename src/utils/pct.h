#pragma once

#include <stddef.h>

/**
 * Percent-decode `len` bytes from `in`. Returns a malloc'd NUL-terminated string,
 * or NULL on OOM, malformed escape, or a decoded NUL byte (%00 is rejected to
 * prevent silent truncation). Caller must free().
 */
char *cotp_pct_decode_n (const char *in, size_t len);

/**
 * Percent-encode a NUL-terminated string per the RFC 3986 unreserved set.
 * Returns a malloc'd NUL-terminated string, or NULL on OOM. Caller must free().
 */
char *cotp_pct_encode (const char *in);
