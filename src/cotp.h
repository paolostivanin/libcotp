#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(__GNUC__) || defined(__clang__)
    #define COTP_API __attribute__((visibility("default")))
    #define COTP_WUR __attribute__((warn_unused_result))
#else
    #define COTP_API
    #define COTP_WUR
#endif

#define COTP_VERSION_MAJOR  4
#define COTP_VERSION_MINOR  1
#define COTP_VERSION_PATCH  0
#define COTP_VERSION_STRING "4.1.0"
#define COTP_VERSION_NUMBER ((COTP_VERSION_MAJOR * 10000) + (COTP_VERSION_MINOR * 100) + COTP_VERSION_PATCH)

#define COTP_SHA1   0
#define COTP_SHA256 1
#define COTP_SHA512 2

#define MIN_DIGITS 4
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

// Opaque context for repeated OTP computations (optional ergonomic API)
typedef struct cotp_ctx cotp_ctx;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef COTP_ENABLE_VALIDATION
/**
 * validate_totp_in_window
 *
 * Validates a user-provided TOTP code within a symmetric time window (in periods) around a timestamp.
 * Returns 1 if it matches for any offset in [-window, +window], 0 otherwise.
 * On success and match, sets matched_delta to the offset that matched (may be 0). On general failure, returns 0 and sets err_code.
 * `window` is clamped to a maximum of 1024 periods; values above that return INVALID_USER_INPUT.
 */
COTP_API COTP_WUR int validate_totp_in_window(const char* user_code,
                            const char* base32_encoded_secret,
                            long        timestamp,
                            int         digits,
                            int         period,
                            int         sha_algo,
                            int         window,
                            int*        matched_delta,
                            cotp_error_t* err_code);

/**
 * cotp_ctx_validate_totp
 *
 * Context-API wrapper around validate_totp_in_window. Uses ctx->digits, ctx->period, ctx->algo.
 * Returns 1 on match, 0 otherwise (or on error). NULL ctx => INVALID_USER_INPUT, returns 0.
 */
COTP_API COTP_WUR int cotp_ctx_validate_totp(cotp_ctx* ctx,
                            const char*   user_code,
                            const char*   base32_encoded_secret,
                            long          timestamp,
                            int           window,
                            int*          matched_delta,
                            cotp_error_t* err);
#endif

/**
 * cotp_strerror
 *
 * Returns a static, NUL-terminated description of the given error code.
 * The returned pointer must NOT be freed. Always returns a non-NULL string;
 * unknown values map to "unknown error".
 */
COTP_API const char *cotp_strerror(cotp_error_t err);

// Context helpers
COTP_API COTP_WUR cotp_ctx* cotp_ctx_create(int digits, int period, int sha_algo);
COTP_API void               cotp_ctx_free(cotp_ctx* ctx);
COTP_API COTP_WUR char*     cotp_ctx_totp_at(cotp_ctx* ctx, const char* base32_encoded_secret, long timestamp, cotp_error_t* err);
COTP_API COTP_WUR char*     cotp_ctx_totp(cotp_ctx* ctx, const char* base32_encoded_secret, cotp_error_t* err);
COTP_API COTP_WUR char*     cotp_ctx_hotp(cotp_ctx* ctx, const char* base32_encoded_secret, long counter, cotp_error_t* err);
// Steam variants ignore ctx->digits and ctx->algo (Steam fixes both); only ctx->period is used.
COTP_API COTP_WUR char*     cotp_ctx_steam_totp(cotp_ctx* ctx, const char* base32_encoded_secret, cotp_error_t* err);
COTP_API COTP_WUR char*     cotp_ctx_steam_totp_at(cotp_ctx* ctx, const char* base32_encoded_secret, long timestamp, cotp_error_t* err);

/**
 * base32_encode
 *
 * Ownership: returns a newly allocated, NUL-terminated string on success; caller must free() it.
 * On error: returns NULL and sets err_code.
 */
COTP_API COTP_WUR char    *base32_encode     (const uint8_t *user_data,
                            size_t        data_len,
                            cotp_error_t *err_code);

/**
 * base32_decode
 *
 * Ownership: returns a newly allocated buffer of length data_len_out on success; caller must free() it.
 * The returned data preserves the input NUL when the original encoded content represented it.
 * On error: returns NULL and sets err_code.
 */
COTP_API COTP_WUR uint8_t *base32_decode     (const char   *user_data_untrimmed,
                            size_t        data_len,
                            cotp_error_t *err_code);

/**
 * is_string_valid_b32
 *
 * Checks whether a string is valid Base32 (ignoring ASCII spaces). Does not allocate.
 */
COTP_API COTP_WUR bool     is_string_valid_b32 (const char *user_data);

/**
 * get_hotp
 *
 * Ownership: returns a newly allocated, zero-padded OTP string of requested width; caller must free().
 * On error: returns NULL and sets err_code.
 */
COTP_API COTP_WUR char    *get_hotp          (const char   *base32_encoded_secret,
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
COTP_API COTP_WUR char    *get_totp          (const char   *base32_encoded_secret,
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
COTP_API COTP_WUR char    *get_steam_totp    (const char   *base32_encoded_secret,
                            int          period,
                            cotp_error_t *err_code);

/**
 * get_totp_at
 *
 * Ownership: returns a newly allocated, zero-padded OTP string; caller must free().
 * On error: returns NULL and sets err_code.
 */
COTP_API COTP_WUR char    *get_totp_at       (const char   *base32_encoded_secret,
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
COTP_API COTP_WUR char    *get_steam_totp_at (const char   *base32_encoded_secret,
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
COTP_API COTP_WUR int64_t  otp_to_int        (const char   *otp,
                            cotp_error_t *err_code);

// otpauth:// URI parser/builder (Google Authenticator de-facto format).
typedef enum {
    COTP_OTPAUTH_TOTP = 0,
    COTP_OTPAUTH_HOTP = 1
} cotp_otpauth_type;

typedef struct {
    cotp_otpauth_type type;
    char *issuer;       // owned, may be NULL
    char *account;      // owned, may be NULL
    char *secret;       // owned, base32-encoded; non-NULL on successful parse
    int   algo;         // COTP_SHA1 / COTP_SHA256 / COTP_SHA512
    int   digits;       // 4-10
    int   period;       // 1-120 (TOTP only)
    long  counter;      // >= 0 (HOTP only)
} cotp_otpauth_uri;

/**
 * cotp_otpauth_uri_parse
 *
 * Parses an otpauth:// URI. On success, returns a heap-allocated struct that the caller must
 * release via cotp_otpauth_uri_free(). Defaults for missing query parameters: algorithm=SHA1,
 * digits=6, period=30. For HOTP the `counter` parameter is required.
 * Returns NULL on error and sets *err. Unknown query keys are silently ignored.
 * If both label-issuer ("Issuer:Account") and "&issuer=" query parameter are present, the label-issuer wins.
 */
COTP_API COTP_WUR cotp_otpauth_uri *cotp_otpauth_uri_parse (const char    *uri,
                                                           cotp_error_t  *err);

/**
 * cotp_otpauth_uri_build
 *
 * Builds an otpauth:// URI from the given struct. Returns a newly allocated NUL-terminated string
 * the caller must free(). Validates fields with the same bounds as get_hotp/get_totp_at; returns
 * NULL with *err set on validation failure or allocation error.
 */
COTP_API COTP_WUR char *cotp_otpauth_uri_build (const cotp_otpauth_uri *u,
                                                cotp_error_t           *err);

/**
 * cotp_otpauth_uri_free
 *
 * Releases a struct returned by cotp_otpauth_uri_parse(). NULL-safe. Securely zeroes the
 * `secret` field before freeing.
 */
COTP_API void cotp_otpauth_uri_free (cotp_otpauth_uri *u);

#ifdef __cplusplus
}
#endif
