#include <criterion/criterion.h>
#include <string.h>
#include <stdlib.h>
#include "../src/cotp.h"

static const char *kYandexUri =
    "otpauth://yaotp/alice%40yandex.ru"
    "?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI"
    "&pin_length=4"
    "&issuer=Yandex"
    "&track_id=abc123"
    "&uid=987654321";

Test(yaotp_uri, parse_basic) {
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (kYandexUri, &err);
    cr_assert_not_null (u);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_str_eq (u->secret, "LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI");
    cr_expect_str_eq (u->account, "alice@yandex.ru");
    cr_expect_str_eq (u->issuer, "Yandex");
    cr_expect_str_eq (u->track_id, "abc123");
    cr_expect_str_eq (u->uid, "987654321");
    cr_expect_eq (u->pin_length, 4);
    cotp_yaotp_uri_free (u);
}

Test(yaotp_uri, parse_minimal) {
    const char *uri = "otpauth://yaotp/user?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI&pin_length=4";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_str_eq (u->account, "user");
    cr_expect_eq (u->pin_length, 4);
    cr_expect_null (u->issuer);
    cr_expect_null (u->track_id);
    cr_expect_null (u->uid);
    cotp_yaotp_uri_free (u);
}

Test(yaotp_uri, name_query_used_when_label_empty) {
    const char *uri = "otpauth://yaotp/?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI&pin_length=4&name=fromname";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_str_eq (u->account, "fromname");
    cotp_yaotp_uri_free (u);
}

Test(yaotp_uri, label_takes_precedence_over_name) {
    const char *uri = "otpauth://yaotp/fromlabel?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI&pin_length=4&name=fromname";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_str_eq (u->account, "fromlabel");
    cotp_yaotp_uri_free (u);
}

Test(yaotp_uri, reject_missing_secret) {
    const char *uri = "otpauth://yaotp/user?pin_length=4";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_expect_null (u);
    cr_expect_eq (err, INVALID_USER_INPUT);
}

Test(yaotp_uri, reject_missing_pin_length) {
    const char *uri = "otpauth://yaotp/user?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_expect_null (u);
    cr_expect_eq (err, INVALID_YAOTP_PIN);
}

Test(yaotp_uri, reject_pin_length_out_of_range_low) {
    const char *uri = "otpauth://yaotp/user?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI&pin_length=3";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_expect_null (u);
    cr_expect_eq (err, INVALID_YAOTP_PIN);
}

Test(yaotp_uri, reject_pin_length_out_of_range_high) {
    const char *uri = "otpauth://yaotp/user?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI&pin_length=17";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_expect_null (u);
    cr_expect_eq (err, INVALID_YAOTP_PIN);
}

Test(yaotp_uri, reject_wrong_scheme) {
    const char *uri = "otpauth://totp/user?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI&pin_length=4";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_expect_null (u);
    cr_expect_eq (err, INVALID_USER_INPUT);
}

Test(yaotp_uri, reject_null) {
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (NULL, &err);
    cr_expect_null (u);
    cr_expect_eq (err, INVALID_USER_INPUT);
}

Test(yaotp_uri, build_round_trip) {
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u1 = cotp_yaotp_uri_parse (kYandexUri, &err);
    cr_assert_not_null (u1);

    char *built = cotp_yaotp_uri_build (u1, &err);
    cr_assert_not_null (built);
    cr_expect_eq (err, NO_ERROR);

    cotp_yaotp_uri *u2 = cotp_yaotp_uri_parse (built, &err);
    cr_assert_not_null (u2);

    cr_expect_str_eq (u2->secret,   u1->secret);
    cr_expect_str_eq (u2->account,  u1->account);
    cr_expect_str_eq (u2->issuer,   u1->issuer);
    cr_expect_str_eq (u2->track_id, u1->track_id);
    cr_expect_str_eq (u2->uid,      u1->uid);
    cr_expect_eq     (u2->pin_length, u1->pin_length);

    free (built);
    cotp_yaotp_uri_free (u1);
    cotp_yaotp_uri_free (u2);
}

Test(yaotp_uri, build_minimal) {
    cotp_yaotp_uri u = {0};
    u.secret     = strdup ("LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI");
    u.pin_length = 4;
    cotp_error_t err = NO_ERROR;
    char *built = cotp_yaotp_uri_build (&u, &err);
    cr_assert_not_null (built);
    cr_expect_eq (err, NO_ERROR);
    // Should not contain optional fields.
    cr_expect_null (strstr (built, "issuer"));
    cr_expect_null (strstr (built, "track_id"));
    cr_expect_null (strstr (built, "uid"));
    cr_expect_not_null (strstr (built, "secret="));
    cr_expect_not_null (strstr (built, "pin_length=4"));
    free (built);
    free (u.secret);
}

Test(yaotp_uri, build_rejects_invalid_pin_length) {
    cotp_yaotp_uri u = {0};
    u.secret     = (char *)"LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI";
    u.pin_length = 0;
    cotp_error_t err = NO_ERROR;
    char *built = cotp_yaotp_uri_build (&u, &err);
    cr_expect_null (built);
    cr_expect_eq (err, INVALID_YAOTP_PIN);
}

Test(yaotp_uri, end_to_end_uri_to_code) {
    // Chain the URI parser to the generator: parse, then feed the extracted secret + PIN
    // straight into get_yaotp_at. Uses the same known-answer vector as test_yaotp.c.
    const char *uri = "otpauth://yaotp/user?secret=LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI&pin_length=4";
    cotp_error_t err = NO_ERROR;
    cotp_yaotp_uri *u = cotp_yaotp_uri_parse (uri, &err);
    cr_assert_not_null (u);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_eq (u->pin_length, 4);

    char *code = get_yaotp_at (u->secret, "7586", 1581064020L, &err);
    cr_assert_not_null (code);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_str_eq (code, "oactmacq");

    free (code);
    cotp_yaotp_uri_free (u);
}

Test(yaotp_uri, build_percent_encodes_account) {
    // '@' is not RFC 3986 unreserved, so the shared pct codec must emit %40 in the label.
    cotp_yaotp_uri u = {0};
    u.secret     = strdup ("LA2V6KMCGYMWWVEW64RNP3JA3IAAAAAAHTSG4HRZPI");
    u.account    = strdup ("alice@yandex.ru");
    u.pin_length = 4;
    cotp_error_t err = NO_ERROR;
    char *built = cotp_yaotp_uri_build (&u, &err);
    cr_assert_not_null (built);
    cr_expect_eq (err, NO_ERROR);
    cr_expect_not_null (strstr (built, "yaotp/alice%40yandex.ru"));
    free (built);
    free (u.secret);
    free (u.account);
}

Test(yaotp_uri, free_null_is_safe) {
    cotp_yaotp_uri_free (NULL);
}
