#pragma once

#include <stddef.h>

/**
 * One-shot SHA-256 over `data`. Writes 32 bytes to `out`.
 * Returns 0 on success, non-zero on backend failure.
 */
int whash_sha256 (const unsigned char *data,
                  size_t               len,
                  unsigned char        out[32]);
