#pragma once
#include <stddef.h>

#if defined(__GNUC__) || defined(__clang__)
    #define COTP_INTERNAL_API __attribute__((visibility("default")))
#else
    #define COTP_INTERNAL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Wipes memory in a way that compilers must not elide. Use for secrets and HMAC outputs.
COTP_INTERNAL_API void cotp_secure_memzero(void *ptr, size_t len);

// Constant-time comparison. Returns 0 if equal, non-zero otherwise.
COTP_INTERNAL_API int cotp_timing_safe_memcmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif
