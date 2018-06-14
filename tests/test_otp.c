#include <criterion/criterion.h>
#include <string.h>
#include <cotp.h>
#include <baseencode.h>


Test(totp_rfc6238, test_8_digits_sha1) {
    const char *K = "12345678901234567890";
    const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
    const char *expected_totp[] = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};

    baseencode_error_t base_err;
    char *K_base32 = base32_encode(K, strlen(K)+1, &base_err);

    cotp_error_t err;
    for (int i = 0; i < 6; i++) {
        char *totp = get_totp_at(K_base32, counter[i], 8, 30, SHA1, &err);
        cr_expect_str_eq(totp, expected_totp[i], "Expected %s to be equal to %s\n", totp, expected_totp[i]);
        free(totp);
    }
    free(K_base32);
}


Test(totp_rfc6238, test_8_digits_sha256) {
    const char *K = "12345678901234567890123456789012";
    const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
    const char *expected_totp[] = {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"};

    baseencode_error_t base_err;
    char *K_base32 = base32_encode(K, strlen(K)+1, &base_err);

    cotp_error_t err;
    for (int i = 0; i < 6; i++) {
        char *totp = get_totp_at(K_base32, counter[i], 8, 30, SHA256, &err);
        cr_expect_str_eq(totp, expected_totp[i], "Expected %s to be equal to %s\n", totp, expected_totp[i]);
        free(totp);
    }
    free(K_base32);
}


Test(totp_rfc6238, test_8_digits_sha512) {
    const char *K = "1234567890123456789012345678901234567890123456789012345678901234";
    const int64_t counter[] = {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000};
    const char *expected_totp[] = {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"};

    baseencode_error_t base_err;
    char *K_base32 = base32_encode(K, strlen(K)+1, &base_err);

    cotp_error_t err;
    for (int i = 0; i < 6; i++) {
        char *totp = get_totp_at(K_base32, counter[i], 8, 30, SHA512, &err);
        cr_expect_str_eq(totp, expected_totp[i], "Expected %s to be equal to %s\n", totp, expected_totp[i]);
        free(totp);
    }
    free(K_base32);
}


Test(hotp_rfc, test_6_digits) {
    const char *K = "12345678901234567890";
    const int counter[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const char *expected_hotp[] = {"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"};

    baseencode_error_t base_err;
    char *K_base32 = base32_encode(K, strlen(K)+1, &base_err);

    cotp_error_t err;
    for (int i = 0; i < 10; i++) {
        char *hotp = get_hotp(K_base32, counter[i], 6, 30, SHA1, &err);
        cr_expect_str_eq(hotp, expected_hotp[i], "Expected %s to be equal to %s\n", hotp, expected_hotp[i]);
        free(hotp);
    }
    free(K_base32);
}


Test(hotp_rfc, test_wrong_digits) {
    const char *K = "this is a secret";

    cotp_error_t err;
    char *totp = get_totp (K, 7, 30, SHA1, &err);

    cr_expect_null (totp, "Expected totp to be null");
    cr_expect_eq (err, INVALID_DIGITS, "Expected %d to be equal to %d\n", err, INVALID_DIGITS);

    free (totp);
}


Test(hotp_rfc, test_wrong_period) {
    const char *K = "this is a secret";

    cotp_error_t err;
    char *totp = get_totp (K, 6, 29, SHA1, &err);

    cr_expect_null (totp, "Expected totp to be null");
    cr_expect_eq (err, INVALID_PERIOD, "Expected %d to be equal to %d\n", err, INVALID_PERIOD);

    free (totp);
}


Test(totp_generic, test_secret_with_space) {
    const char *K = "hxdm vjec jjws rb3h wizr 4ifu gftm xboz";
    const char *expected_totp = "488431";

    cotp_error_t err;
    char *totp = get_totp_at (K, 1506268800, 6, 30, SHA1, &err);
    cr_expect_str_eq (totp, expected_totp, "Expected %s to be equal to %s\n", totp, expected_totp);

    free (totp);
}


Test(totp_generic, test_fail_invalid_b32_input) {
    const char *K = "This input is not valid!";

    cotp_error_t err;
    char *totp = get_totp (K, 6, 30, SHA1, &err);

    cr_expect_null (totp, "Expected totp to be null");
    cr_expect_eq (err, INVALID_B32_INPUT, "Expected %d to be equal to %d\n", err, INVALID_B32_INPUT);
}


Test(totp_generic, test_fail_invalid_algo) {
    const char *K = "base32secret";

    cotp_error_t err;
    char *totp = get_totp (K, 6, 30, GCRY_MD_MD5, &err);

    cr_expect_null (totp, "Expected totp to be null");
    cr_expect_eq (err, INVALID_ALGO, "Expected %d to be equal to %d\n", err, INVALID_ALGO);
}


Test(totp_generic, test_steam_totp) {
    const char *secret = "ON2XAZLSMR2XAZLSONSWG4TFOQ======";
    const char *expected_totp = "YRGQJ";
    long timestamp = 3000030;

    cotp_error_t err;
    char *totp = get_steam_totp_at (secret, timestamp, 30, &err);
    cr_expect_str_eq (totp, expected_totp, "Expected %s to be equal to %s\n", totp, expected_totp);

    free (totp);
}


Test(totp_generic, test_steam_totp_input_b64) {
    const char *b64_encoded_secret = "VGhpcyBpbnB1dCBpcyBub3QgdmFsaWQhCg==";

    cotp_error_t err;
    char *totp = get_steam_totp (b64_encoded_secret, 30, &err);
    cr_expect_null (totp, "Expected totp to be null");
    cr_expect_eq (err, INVALID_B32_INPUT, "Expected %d to be equal to %d\n", err, INVALID_B32_INPUT);
}
