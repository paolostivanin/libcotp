#include <criterion/criterion.h>
#include <string.h>
#include <stdlib.h>
#include "../src/cotp.h"

Test(otpauth, parse_google_example) {
    const char *uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    cotp_error_t err = NO_ERROR;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_eq (u->type, COTP_OTPAUTH_TOTP);
    cr_expect_str_eq (u->issuer, "Example");
    cr_expect_str_eq (u->account, "alice@google.com");
    cr_expect_str_eq (u->secret, "JBSWY3DPEHPK3PXP");
    cr_expect_eq (u->algo, COTP_SHA1);
    cr_expect_eq (u->digits, 6);
    cr_expect_eq (u->period, 30);
    cotp_otpauth_uri_free (u);
}


Test(otpauth, parse_totp_defaults) {
    // No algorithm/digits/period → SHA1/6/30
    const char *uri = "otpauth://totp/user?secret=JBSWY3DPEHPK3PXP";
    cotp_error_t err = NO_ERROR;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_null (u->issuer);
    cr_expect_str_eq (u->account, "user");
    cr_expect_eq (u->algo, COTP_SHA1);
    cr_expect_eq (u->digits, 6);
    cr_expect_eq (u->period, 30);
    cotp_otpauth_uri_free (u);
}


Test(otpauth, parse_totp_custom) {
    const char *uri = "otpauth://totp/Foo:bar?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=60";
    cotp_error_t err = NO_ERROR;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_eq (u->algo, COTP_SHA512);
    cr_expect_eq (u->digits, 8);
    cr_expect_eq (u->period, 60);
    cotp_otpauth_uri_free (u);
}


Test(otpauth, parse_hotp_with_counter) {
    const char *uri = "otpauth://hotp/acct?secret=JBSWY3DPEHPK3PXP&counter=42";
    cotp_error_t err = NO_ERROR;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_eq (u->type, COTP_OTPAUTH_HOTP);
    cr_expect_eq (u->counter, 42);
    cotp_otpauth_uri_free (u);
}


Test(otpauth, parse_hotp_missing_counter_rejected) {
    const char *uri = "otpauth://hotp/acct?secret=JBSWY3DPEHPK3PXP";
    cotp_error_t err = NO_ERROR;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (uri, &err);
    cr_expect_null (u);
    cr_expect_eq (err, INVALID_COUNTER);
}


Test(otpauth, parse_url_encoded_label) {
    // "Example Co:alice" with space pct-encoded
    const char *uri = "otpauth://totp/Example%20Co:alice?secret=JBSWY3DPEHPK3PXP";
    cotp_error_t err = NO_ERROR;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_str_eq (u->issuer, "Example Co");
    cr_expect_str_eq (u->account, "alice");
    cotp_otpauth_uri_free (u);
}


Test(otpauth, parse_label_issuer_wins_over_query_issuer) {
    const char *uri = "otpauth://totp/Foo:bar?secret=JBSWY3DPEHPK3PXP&issuer=Bar";
    cotp_error_t err = NO_ERROR;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_str_eq (u->issuer, "Foo");
    cotp_otpauth_uri_free (u);
}


Test(otpauth, parse_invalid_scheme) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("https://example.com/", &err));
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(otpauth, parse_null_input) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse (NULL, &err));
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(otpauth, parse_missing_secret_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp/x?digits=6", &err));
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(otpauth, parse_invalid_algo_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", &err));
    cr_expect_eq (err, INVALID_ALGO);
}


Test(otpauth, parse_invalid_digits_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=2", &err));
    cr_expect_eq (err, INVALID_DIGITS);
}


Test(otpauth, parse_invalid_period_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=200", &err));
    cr_expect_eq (err, INVALID_PERIOD);
}


Test(otpauth, parse_invalid_b32_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp/x?secret=NOTBASE32!!!", &err));
    cr_expect_eq (err, INVALID_B32_INPUT);
}


Test(otpauth, parse_unknown_keys_ignored) {
    // unknown keys silently ignored
    const char *uri = "otpauth://totp/u?secret=JBSWY3DPEHPK3PXP&foo=bar&xyz=abc";
    cotp_error_t err = NO_ERROR;
    cotp_otpauth_uri *u = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cotp_otpauth_uri_free (u);
}


Test(otpauth, build_totp_minimal) {
    cotp_otpauth_uri u = {0};
    u.type = COTP_OTPAUTH_TOTP;
    u.secret = (char *)"JBSWY3DPEHPK3PXP";
    u.algo = COTP_SHA1;
    u.digits = 6;
    u.period = 30;

    cotp_error_t err = NO_ERROR;
    char *uri = cotp_otpauth_uri_build (&u, &err);
    cr_assert_not_null (uri);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_neq (strstr (uri, "otpauth://totp/"), NULL);
    cr_expect_neq (strstr (uri, "secret=JBSWY3DPEHPK3PXP"), NULL);
    cr_expect_neq (strstr (uri, "algorithm=SHA1"), NULL);
    cr_expect_neq (strstr (uri, "digits=6"), NULL);
    cr_expect_neq (strstr (uri, "period=30"), NULL);
    free (uri);
}


Test(otpauth, build_then_parse_round_trip_totp) {
    cotp_otpauth_uri u = {0};
    u.type = COTP_OTPAUTH_TOTP;
    u.issuer = (char *)"Example Co";
    u.account = (char *)"alice@example.com";
    u.secret = (char *)"JBSWY3DPEHPK3PXP";
    u.algo = COTP_SHA256;
    u.digits = 8;
    u.period = 60;

    cotp_error_t err = NO_ERROR;
    char *uri = cotp_otpauth_uri_build (&u, &err);
    cr_assert_not_null (uri);

    cotp_otpauth_uri *back = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (back);
    cr_expect_eq (back->type, COTP_OTPAUTH_TOTP);
    cr_expect_str_eq (back->issuer, "Example Co");
    cr_expect_str_eq (back->account, "alice@example.com");
    cr_expect_str_eq (back->secret, "JBSWY3DPEHPK3PXP");
    cr_expect_eq (back->algo, COTP_SHA256);
    cr_expect_eq (back->digits, 8);
    cr_expect_eq (back->period, 60);

    cotp_otpauth_uri_free (back);
    free (uri);
}


Test(otpauth, build_then_parse_round_trip_hotp) {
    cotp_otpauth_uri u = {0};
    u.type = COTP_OTPAUTH_HOTP;
    u.account = (char *)"acct";
    u.secret = (char *)"JBSWY3DPEHPK3PXP";
    u.algo = COTP_SHA1;
    u.digits = 6;
    u.counter = 12345;

    cotp_error_t err = NO_ERROR;
    char *uri = cotp_otpauth_uri_build (&u, &err);
    cr_assert_not_null (uri);

    cotp_otpauth_uri *back = cotp_otpauth_uri_parse (uri, &err);
    cr_assert_not_null (back);
    cr_expect_eq (back->type, COTP_OTPAUTH_HOTP);
    cr_expect_eq (back->counter, 12345);

    cotp_otpauth_uri_free (back);
    free (uri);
}


Test(otpauth, build_rejects_invalid_secret) {
    cotp_otpauth_uri u = {0};
    u.type = COTP_OTPAUTH_TOTP;
    u.secret = (char *)"NOT BASE32 !!!";
    u.algo = COTP_SHA1;
    u.digits = 6;
    u.period = 30;

    cotp_error_t err = NO_ERROR;
    char *uri = cotp_otpauth_uri_build (&u, &err);
    cr_expect_null (uri);
    cr_expect_eq (err, INVALID_B32_INPUT);
}


Test(otpauth, free_null_safe) {
    cotp_otpauth_uri_free (NULL);  // must not crash
}


Test(otpauth, parse_malformed_pct_encoding_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp/x?secret=AB%GG", &err));
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(otpauth, parse_pct_null_byte_rejected) {
    // %00 in any percent-decoded field would silently truncate the resulting C string;
    // the parser must reject it.
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp/x?secret=AB%00CD", &err));
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(otpauth, parse_no_slash_after_type_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp", &err));
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(otpauth, parse_invalid_type_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://foo/x?secret=JBSWY3DPEHPK3PXP", &err));
    cr_expect_eq (err, INVALID_USER_INPUT);
}


Test(otpauth, parse_negative_hotp_counter_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=-5", &err));
    cr_expect_eq (err, INVALID_COUNTER);
}


Test(otpauth, parse_empty_secret_value_rejected) {
    cotp_error_t err = NO_ERROR;
    cr_expect_null (cotp_otpauth_uri_parse ("otpauth://totp/x?secret=", &err));
    cr_expect_eq (err, INVALID_USER_INPUT);
}
