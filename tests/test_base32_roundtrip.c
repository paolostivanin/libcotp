#include <criterion/criterion.h>
#include <string.h>
#include <ctype.h>
#include "../src/cotp.h"

// Round-trip helper: encode raw -> base32, then decode back, compare
static void roundtrip_check(const char* raw)
{
    cotp_error_t err = 0;
    size_t raw_len = strlen(raw) + 1; // keep terminating NUL like other tests
    char* b32 = base32_encode((const uchar*)raw, raw_len, &err);
    cr_expect_not_null(b32);
    cr_expect_eq(err, 0);

    uchar* decoded = base32_decode(b32, strlen(b32) + 1, &err);
    cr_expect_not_null(decoded);
    cr_expect_eq(err, 0);
    cr_expect_arr_eq(decoded, raw, raw_len);

    free(b32);
    free(decoded);
}

Test(base32_roundtrip, small_corpus)
{
    roundtrip_check("");
    roundtrip_check("a");
    roundtrip_check("ab");
    roundtrip_check("abc");
    roundtrip_check("abcd");
    roundtrip_check("abcde");
    roundtrip_check("abcdef");
    roundtrip_check("abcdefg");
    roundtrip_check("abcdefgh");
}

Test(base32_decoder, accepts_spaces_and_case)
{
    // These variants should decode to the same bytes
    const char* raw = "hello world";
    cotp_error_t err = 0;
    char* b32_norm = base32_encode((const uchar*)raw, strlen(raw) + 1, &err);
    cr_expect_eq(err, 0);

    // introduce spaces and lower case
    char messy[256];
    size_t L = strlen(b32_norm);
    size_t j = 0;
    for (size_t i = 0; i < L; ++i) {
        char c = b32_norm[i];
        // insert a space occasionally
        if (i % 4 == 0) messy[j++] = ' ';
        messy[j++] = (char) (i % 2 == 0 ? c : (char)tolower((unsigned char)c));
    }
    messy[j] = '\0';

    uchar* d1 = base32_decode(b32_norm, strlen(b32_norm) + 1, &err);
    cr_expect_eq(err, 0);
    uchar* d2 = base32_decode(messy, strlen(messy) + 1, &err);
    cr_expect_eq(err, 0);
    cr_expect_str_eq((char*)d1, (char*)d2, "%s");

    free(b32_norm);
    free(d1);
    free(d2);
}
