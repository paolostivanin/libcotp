#include "secure_zero.h"
#include <string.h>

#if defined(_MSC_VER)
#include <windows.h>
#endif

void cotp_secure_memzero(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return;

    #if defined(__STDC_LIB_EXT1__)
        memset_s(ptr, len, 0, len);
        return;
    #elif defined(HAVE_EXPLICIT_BZERO)
        explicit_bzero(ptr, len);
        return;
    #elif defined(_MSC_VER)
        SecureZeroMemory(ptr, len);
        return;
    #else
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (len--) {
            *p++ = 0;
        }
        return;
    #endif
}

int cotp_timing_safe_memcmp(const void *a, const void *b, size_t len) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (unsigned char)(pa[i] ^ pb[i]);
    }
    return diff; // 0 if equal
}
