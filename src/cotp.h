#pragma once
#include <gcrypt.h>
#include <stdint.h>

#define SHA1 GCRY_MD_SHA1
#define SHA256 GCRY_MD_SHA256
#define SHA512 GCRY_MD_SHA512

typedef enum {
    NO_ERROR = 0,
    VALID,
    GCRYPT_VERSION_MISMATCH,
    INVALID_B32_INPUT,
    INVALID_ALGO,
    INVALID_OTP,
    INVALID_DIGITS,
    INVALID_PERIOD,
    MEMORY_ALLOCATION_ERROR,
    INVALID_USER_INPUT,
    EMPTY_STRING
} cotp_error_t;

#ifdef __cplusplus
extern "C" {
#endif

char *base32_encode     (const uint8_t       *user_data,
                         size_t               data_len,
                         cotp_error_t        *err_code);

uint8_t *base32_decode  (const char          *user_data_untrimmed,
                         size_t               data_len,
                         cotp_error_t        *err_code);

char *get_hotp          (const char          *base32_encoded_secret,
                         long                 counter,
                         int                  digits,
                         int                  sha_algo,
                         cotp_error_t        *err_code);

char *get_totp          (const char          *base32_encoded_secret,
                         int                  digits,
                         int                  period,
                         int                  sha_algo,
                         cotp_error_t        *err_code);

char *get_steam_totp    (const char          *base32_encoded_secret,
                         int                  period,
                         cotp_error_t        *err_code);


char *get_totp_at       (const char          *base32_encoded_secret,
                         long                 time,
                         int                  digits,
                         int                  period,
                         int                  sha_algo,
                         cotp_error_t        *err_code);

char *get_steam_totp_at (const char          *base32_encoded_secret,
                         long                 timestamp,
                         int                  period,
                         cotp_error_t        *err_code);

int   totp_verify       (const char          *base32_encoded_secret,
                         const char          *user_totp,
                         int                  digits,
                         int                  period,
                         int                  sha_algo);

int   hotp_verify       (const char          *base32_encoded_secret,
                         long                 counter,
                         int                  digits,
                         const char          *user_hotp,
                         int                  sha_algo);

#ifdef __cplusplus
}
#endif
