#pragma once
#include <stdint.h>
#include <stdbool.h>

#define COTP_SHA1 0
#define COTP_SHA256 1
#define COTP_SHA512 2

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

// Opaque context for repeated OTP computations (optional ergonomic API)
typedef struct cotp_ctx cotp_ctx;

#ifdef __cplusplus
extern "C" {
#endif

extern const uint8_t b32_alphabet[];

#ifdef COTP_ENABLE_VALIDATION
/**
 * validate_totp_in_window
 *
 * Validates a user-provided TOTP code within a symmetric time window (in periods) around a timestamp.
 * Returns 1 if it matches for any offset in [-window, +window], 0 otherwise.
 * On success and match, sets matched_delta to the offset that matched (may be 0). On general failure, returns 0 and sets err_code.
 */
int validate_totp_in_window(const char* user_code,
                            const char* base32_encoded_secret,
                            long        timestamp,
                            int         digits,
                            int         period,
                            int         sha_algo,
                            int         window,
                            int*        matched_delta,
                            cotp_error_t* err_code);
#endif

// Context helpers
cotp_ctx* cotp_ctx_create(int digits, int period, int sha_algo);
void      cotp_ctx_free(cotp_ctx* ctx);
char*     cotp_ctx_totp_at(cotp_ctx* ctx, const char* base32_encoded_secret, long timestamp, cotp_error_t* err);
char*     cotp_ctx_totp(cotp_ctx* ctx, const char* base32_encoded_secret, cotp_error_t* err);

/**
 * base32_encode
 *
 * Ownership: returns a newly allocated, NUL-terminated string on success; caller must free() it.
 * On error: returns NULL and sets err_code.
 */
char    *base32_encode     (const uchar  *user_data,
                            size_t        data_len,
                            cotp_error_t *err_code);

/**
 * base32_decode
 *
 * Ownership: returns a newly allocated buffer of length data_len_out on success; caller must free() it.
 * The returned data preserves the input NUL when the original encoded content represented it.
 * On error: returns NULL and sets err_code.
 */
uchar   *base32_decode     (const char   *user_data_untrimmed,
                            size_t        data_len,
                            cotp_error_t *err_code);

/**
 * is_string_valid_b32
 *
 * Checks whether a string is valid Base32 (ignoring ASCII spaces). Does not allocate.
 */
bool     is_string_valid_b32 (const char *user_data);

/**
 * get_hotp
 *
 * Ownership: returns a newly allocated, zero-padded OTP string of requested width; caller must free().
 * On error: returns NULL and sets err_code.
 */
char    *get_hotp          (const char   *base32_encoded_secret,
                            long          counter,
                            int           digits,
                            int           sha_algo,
                            cotp_error_t *err_code);

/**
 * get_totp
 *
 * Ownership: returns a newly allocated, zero-padded OTP string; caller must free().
 * On error: returns NULL and sets err_code.
 */
char    *get_totp          (const char   *base32_encoded_secret,
                            int           digits,
                            int           period,
                            int           sha_algo,
                            cotp_error_t *err_code);

/**
 * get_steam_totp
 *
 * Ownership: returns a newly allocated Steam-style OTP string; caller must free().
 * On error: returns NULL and sets err_code.
 */
char    *get_steam_totp    (const char   *base32_encoded_secret,
                            int          period,
                            cotp_error_t *err_code);

/**
 * get_totp_at
 *
 * Ownership: returns a newly allocated, zero-padded OTP string; caller must free().
 * On error: returns NULL and sets err_code.
 */
char    *get_totp_at       (const char   *base32_encoded_secret,
                            long          time,
                            int           digits,
                            int           period,
                            int           sha_algo,
                            cotp_error_t *err_code);

/**
 * get_steam_totp_at
 *
 * Ownership: returns a newly allocated Steam-style OTP string; caller must free().
 * On error: returns NULL and sets err_code.
 */
char    *get_steam_totp_at (const char   *base32_encoded_secret,
                            long          timestamp,
                            int           period,
                            cotp_error_t *err_code);

/**
 * otp_to_int
 *
 * Converts a digit string (e.g., from get_totp/get_hotp) to an integer. If leading zeros are present,
 * the returned integer will naturally drop them; err_code is set to MISSING_LEADING_ZERO in that case.
 * On invalid input returns -1 and sets err_code to INVALID_USER_INPUT.
 */
int64_t  otp_to_int        (const char   *otp,
                            cotp_error_t *err_code);

#ifdef __cplusplus
}
#endif
