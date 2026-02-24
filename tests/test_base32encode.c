#include <stdio.h>
#include <criterion/criterion.h>
#include "../src/cotp.h"


Test(b32_encode_test, null_input) {
    cotp_error_t err;
    const char *k = NULL;

    char *ek = base32_encode (k, 5, &err);

    cr_expect_null (ek, "%s");
}


Test(b32_encode_test, invalid_or_empty) {
    cotp_error_t err;

    base32_encode (NULL, 30, &err);
    cr_expect_eq (err, INVALID_USER_INPUT);

    char *k_enc = base32_encode ((const unsigned char *)"asdiasjdijis", 0, &err);
    cr_expect (strcmp (k_enc, "") == 0, "Expected %s to be equal to %s", k_enc, "");
    cr_expect_eq (err, EMPTY_STRING);

    free (k_enc);
}


Test(b32_encode_test, byte_array_all_zeroes) {
    cotp_error_t err;
    const char *expected_enc = "AAAAAAA=";

    uint8_t secret_bytes[] = {0, 0, 0, 0};
    char *enc = base32_encode(secret_bytes, 4, &err);

    cr_expect (strcmp (enc, expected_enc) == 0, "Expected %s to be equal to %s", enc, expected_enc);
    free (enc);
}


Test(b32_encode_test, array_allzeroes_utf8) {
    cotp_error_t err;
    const char *expected_enc = "GAYDAMA=";

    char *enc = base32_encode((const unsigned char *)"0000", 4, &err);

    cr_expect (strcmp (enc, expected_enc) == 0, "Expected %s to be equal to %s", enc, expected_enc);
    free (enc);
}


Test(b32_encode_test, b32_all_chars) {
    cotp_error_t err;
    const char *k = "ADFG413!£$%&&((/?^çé*[]#)-.,|<>+";
    const char *k_enc = "IFCEMRZUGEZSDQVDEQSSMJRIFAXT6XWDU7B2SKS3LURSSLJOFR6DYPRL";

    char *ek = base32_encode (k, strlen(k), &err);

    cr_expect (strcmp (ek, k_enc) == 0, "Expected %s to be equal to %s", ek, k_enc);

    free (ek);
}


Test(b32_encode_test, b32_all_chars_plusone) {
    cotp_error_t err;
    const char *k = "ADFG413!£$%&&((/?^çé*[]#)-.,|<>+";
    const char *k_enc = "IFCEMRZUGEZSDQVDEQSSMJRIFAXT6XWDU7B2SKS3LURSSLJOFR6DYPRL";

    char *ek = base32_encode (k, strlen(k)+1, &err);

    cr_expect (strcmp (ek, k_enc) == 0, "Expected %s to be equal to %s", ek, k_enc);

    free (ek);
}


Test(b32_encode_test, b32_rfc4648) {
    cotp_error_t err;
    const char *k[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    const char *k_enc[] = {"", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"};

    for (int i = 0; i < 7; i++) {
        char *ek = base32_encode (k[i], strlen(k[i]), &err);
        cr_expect (strcmp (ek, k_enc[i]) == 0, "Expected %s to be equal to %s", ek, k_enc[i]);
        free (ek);
    }
}


Test(b32_encode_test, b32_rfc4648_plusone) {
    cotp_error_t err;
    const char *k[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    const char *k_enc[] = {"", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"};

    for (int i = 0; i < 7; i++) {
        char *ek = base32_encode (k[i], strlen(k[i])+1, &err);
        cr_expect (strcmp (ek, k_enc[i]) == 0, "Expected %s to be equal to %s", ek, k_enc[i]);
        free (ek);
    }
}


Test(b32_encode_test, b32_rfc4648_noplusone) {
    cotp_error_t err;
    const char *k[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    const char *k_enc[] = {"", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"};

    for (int i = 0; i < 7; i++) {
        char *ek = base32_encode (k[i], strlen(k[i]), &err);
        cr_expect (strcmp (ek, k_enc[i]) == 0, "Expected %s to be equal to %s", ek, k_enc[i]);
        free (ek);
    }
}


Test(b32_encode_test, b32_encode_input_exceeded) {
    cotp_error_t err;
    const char *k = "test";
    size_t len = 65*1024*1024;

    char *ek = base32_encode (k, len, &err);
    cr_expect_null (ek, "%s");
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(b32_encode_test, test_input_all_zeroes) {
    cotp_error_t err;
    const uint8_t secret_bytes[] = {0, 0, 0, 0};

    char *encoded_str = base32_encode (secret_bytes, 4, &err);

    cr_expect_eq (err, NO_ERROR);
    cr_expect (strcmp (encoded_str, "AAAAAAA=") == 0, "Expected %s to be equal to %s", encoded_str, "AAAAAAA=");

    free (encoded_str);
}