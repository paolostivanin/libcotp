#pragma once
#include <stdint.h>
#include <stdbool.h>

#define SHA1 0
#define SHA256 1
#define SHA512 2

#define MIN_DIGTS 4
#define MAX_DIGITS 10

typedef enum cotp_error {
    NO_ERROR = 0,
    VALID,
    WCRYPT_VERSION_MISMATCH,
    INVALID_B32_INPUT,
    INVALID_ALGO,
    INVALID_DIGITS,
    INVALID_PERIOD,
    MEMORY_ALLOCATION_ERROR,
    INVALID_USER_INPUT,
    EMPTY_STRING,
    MISSING_LEADING_ZERO,
    INVALID_COUNTER,
    WHMAC_ERROR
} cotp_error_t;

typedef unsigned char uchar;

#ifdef __cplusplus
extern "C" {
#endif

extern const uint8_t b32_alphabet[];

char    *base32_encode     (const uchar  *user_data,
                            size_t        data_len,
                            cotp_error_t *err_code);

uchar   *base32_decode     (const char   *user_data_untrimmed,
                            size_t        data_len,
                            cotp_error_t *err_code);

bool     is_string_valid_b32 (const char *user_data);

char    *get_hotp          (const char   *base32_encoded_secret,
                            long          counter,
                            int           digits,
                            int           sha_algo,
                            cotp_error_t *err_code);

char    *get_totp          (const char   *base32_encoded_secret,
                            int           digits,
                            int           period,
                            int           sha_algo,
                            cotp_error_t *err_code);

char    *get_steam_totp    (const char   *base32_encoded_secret,
                            int          period,
                            cotp_error_t *err_code);

char    *get_totp_at       (const char   *base32_encoded_secret,
                            long          time,
                            int           digits,
                            int           period,
                            int           sha_algo,
                            cotp_error_t *err_code);

char    *get_steam_totp_at (const char   *base32_encoded_secret,
                            long          timestamp,
                            int           period,
                            cotp_error_t *err_code);

int64_t  otp_to_int        (const char   *otp,
                            cotp_error_t *err_code);

#ifdef __cplusplus
}
#endif
