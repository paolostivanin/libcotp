#include <stdio.h>
#include <criterion/criterion.h>
#include "../src/cotp.h"


Test(b32_encode_test, null_input) {
    cotp_error_t err;
    const char *k = NULL;

    char *ek = base32_encode (k, 5, &err);

    cr_expect_null (ek, "%s");
}


Test(b32_encode_test, data_nodata_size_nosize) {
    cotp_error_t err;
    const char *k1 = "";
    const char *k2 = "asdiasjdijis";

    // test no-data with given size, data with no-size and no-data no-size
    char *ek1 = base32_encode (k1, 30, &err);
    char *ek2 = base32_encode (k2, 0, &err);

    cr_expect (strcmp (k1, ek1) == 0, "Expected %s to be equal to %s", ek1, k1);
    cr_expect_null (ek2, "%s");

    free (ek1);
}


Test(b32_encode_test, b32_all_chars) {
    cotp_error_t err;
    const char *k = "ADFG413!£$%&&((/?^çé*[]#)-.,|<>+";
    const char *k_enc = "IFCEMRZUGEZSDQVDEQSSMJRIFAXT6XWDU7B2SKS3LURSSLJOFR6DYPRL";

    char *ek = base32_encode (k, strlen(k)+1, &err);

    cr_expect (strcmp (ek, k_enc) == 0, "Expected %s to be equal to %s", ek, k_enc);

    free (ek);
}


Test(b32_encode_test, b32_all_chars_noplusone) {
    cotp_error_t err;
    const char *k = "ADFG413!£$%&&((/?^çé*[]#)-.,|<>+";
    const char *k_enc = "IFCEMRZUGEZSDQVDEQSSMJRIFAXT6XWDU7B2SKS3LURSSLJOFR6DYPRL";

    char *ek = base32_encode (k, strlen(k), &err);

    cr_expect (strcmp (ek, k_enc) == 0, "Expected %s to be equal to %s", ek, k_enc);

    free (ek);
}


Test(b32_encode_test, b32_rfc4648) {
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