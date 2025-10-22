#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Wipes memory in a way that compilers must not elide. Use for secrets and HMAC outputs.
void cotp_secure_memzero(void *ptr, size_t len);

// Constant-time comparison. Returns 0 if equal, non-zero otherwise.
int cotp_timing_safe_memcmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif
