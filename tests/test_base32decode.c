#include <stdio.h>
#include <criterion/criterion.h>
#include "../src/cotp.h"


Test(b32_decode_test, b32_all_chars) {
    cotp_error_t err;
    const char *k = "IFCEMRZUGEZSDQVDEQSSMJRIFAXT6XWDU7B2SKS3LURSSLJOFR6DYPRL";
    const char *k_dec = "ADFG413!£$%&&((/?^çé*[]#)-.,|<>+";

    char *dk = base32_decode (k, strlen(k)+1, &err);

    cr_expect(strcmp(dk, k_dec) == 0, "Expected %s to be equal to %s", dk, k_dec);

    free(dk);
}


Test(b32_decode_test, b32_all_chars_noplusone) {
    cotp_error_t err;
    const char *k = "IFCEMRZUGEZSDQVDEQSSMJRIFAXT6XWDU7B2SKS3LURSSLJOFR6DYPRL";
    const char *k_dec = "ADFG413!£$%&&((/?^çé*[]#)-.,|<>+";

    char *dk = base32_decode (k, strlen(k), &err);

    cr_expect(strcmp(dk, k_dec) == 0, "Expected %s to be equal to %s", dk, k_dec);

    free(dk);
}


Test(b32_decode_test, b32_rfc4648) {
    cotp_error_t err;
    const char *k[] = {"", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"};
    const char *k_dec[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};

    for (int i = 0; i < 7; i++) {
        char *dk = base32_decode (k[i], strlen(k[i])+1, &err);
        cr_expect(strcmp(dk, k_dec[i]) == 0, "Expected %s to be equal to %s", dk, k_dec[i]);
        free(dk);
    }
}


Test(b32_decode_test, b32_rfc4648_noplusone) {
    cotp_error_t err;
    const char *k[] = {"", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"};
    const char *k_dec[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};

    for (int i = 0; i < 7; i++) {
        char *dk = base32_decode (k[i], strlen(k[i]), &err);
        cr_expect(strcmp(dk, k_dec[i]) == 0, "Expected %s to be equal to %s", dk, k_dec[i]);
        free(dk);
    }
}


Test(b32_decode_test, b32_invalid_input) {
    cotp_error_t err;
    const char *k = "£&/(&/";
    size_t len = strlen(k);

    uint8_t *dk = base32_decode (k, len, &err);

    cr_expect_null (dk, "%s");
    cr_expect_eq (err, INVALID_B32_INPUT);
}


Test(b32_decode_test, b32_decode_input_exceeded) {
    cotp_error_t err;
    const char *k = "ASDF";
    size_t len = 128*1024*1024;

    uint8_t *dk = base32_decode (k, len, &err);

    cr_expect_null (dk, "%s");
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(b32_decode_test, b32_decode_input_whitespaces) {
    cotp_error_t err;
    const char *k = "MZ XW 6Y TB";
    const char *expected = "fooba";

    uint8_t *dk = base32_decode (k, strlen(k), &err);

    cr_expect_str_eq (dk, expected, "%s");
}

Test(b32_decode_test, b32_decode_encode_null) {
    const char* token = "LLFTSZYMUGKHEDQBAAACAZAMUFKKVFLS";
    cotp_error_t err;

    uint8_t* binary = base32_decode (token, strlen(token)+1, &err);
    cr_expect_eq (err, NO_ERROR);

    char* result = base32_encode (binary, 20, &err);
    cr_expect_eq (err, NO_ERROR);

    cr_expect_str_eq (result, token, "%s");
}

