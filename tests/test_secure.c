#include <criterion/criterion.h>
#include <string.h>
#include "../src/cotp.h"

Test(secure_memzero, zeroes_buffer) {
    unsigned char buf[64];
    memset (buf, 0xA5, sizeof buf);
    cotp_secure_memzero (buf, sizeof buf);
    for (size_t i = 0; i < sizeof buf; i++) {
        cr_expect_eq (buf[i], 0, "byte %zu was not zeroed (got 0x%02x)", i, buf[i]);
    }
}

Test(secure_memzero, null_or_zero_len_is_safe) {
    cotp_secure_memzero (NULL, 0);
    cotp_secure_memzero (NULL, 16);

    unsigned char buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    cotp_secure_memzero (buf, 0);
    cr_expect_eq (buf[0], 1, "len=0 must not modify the buffer");
    cr_expect_eq (buf[7], 8, "len=0 must not modify the buffer");
}

Test(timing_safe_memcmp, equal_returns_zero) {
    const unsigned char a[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    const unsigned char b[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    cr_expect_eq (cotp_timing_safe_memcmp (a, b, sizeof a), 0);
}

Test(timing_safe_memcmp, differ_first_byte_returns_nonzero) {
    const unsigned char a[] = { 0xFF, 0x11, 0x22, 0x33 };
    const unsigned char b[] = { 0x00, 0x11, 0x22, 0x33 };
    cr_expect_neq (cotp_timing_safe_memcmp (a, b, sizeof a), 0);
}

Test(timing_safe_memcmp, differ_last_byte_returns_nonzero) {
    const unsigned char a[] = { 0x11, 0x22, 0x33, 0x44 };
    const unsigned char b[] = { 0x11, 0x22, 0x33, 0x45 };
    cr_expect_neq (cotp_timing_safe_memcmp (a, b, sizeof a), 0);
}

Test(timing_safe_memcmp, zero_length_returns_zero) {
    cr_expect_eq (cotp_timing_safe_memcmp ("a", "b", 0), 0);
}

Test(timing_safe_memcmp, single_bit_difference_returns_nonzero) {
    const unsigned char a[] = { 0x00, 0x00, 0x00, 0x01 };
    const unsigned char b[] = { 0x00, 0x00, 0x00, 0x00 };
    cr_expect_neq (cotp_timing_safe_memcmp (a, b, sizeof a), 0);
}
