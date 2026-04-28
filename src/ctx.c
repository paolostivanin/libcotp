#include <stdlib.h>
#include "cotp.h"

struct cotp_ctx {
    int digits;
    int period;
    int algo;
};

cotp_ctx* cotp_ctx_create(int digits, int period, int sha_algo)
{
    if (digits < MIN_DIGITS || digits > MAX_DIGITS) {
        return NULL;
    }
    if (period <= 0 || period > 120) {
        return NULL;
    }
    if (sha_algo != COTP_SHA1 && sha_algo != COTP_SHA256 && sha_algo != COTP_SHA512) {
        return NULL;
    }

    cotp_ctx* ctx = (cotp_ctx*)calloc(1, sizeof(cotp_ctx));
    if (!ctx) return NULL;
    ctx->digits = digits;
    ctx->period = period;
    ctx->algo = sha_algo;
    return ctx;
}

void cotp_ctx_free(cotp_ctx* ctx)
{
    if (!ctx) return;
    free(ctx);
}

char* cotp_ctx_totp_at(cotp_ctx* ctx, const char* base32_encoded_secret, long timestamp, cotp_error_t* err)
{
    if (!ctx) {
        if (err) *err = INVALID_USER_INPUT;
        return NULL;
    }
    return get_totp_at(base32_encoded_secret, timestamp, ctx->digits, ctx->period, ctx->algo, err);
}

char* cotp_ctx_totp(cotp_ctx* ctx, const char* base32_encoded_secret, cotp_error_t* err)
{
    if (!ctx) {
        if (err) *err = INVALID_USER_INPUT;
        return NULL;
    }
    return get_totp(base32_encoded_secret, ctx->digits, ctx->period, ctx->algo, err);
}

char* cotp_ctx_hotp(cotp_ctx* ctx, const char* base32_encoded_secret, long counter, cotp_error_t* err)
{
    if (!ctx) {
        if (err) *err = INVALID_USER_INPUT;
        return NULL;
    }
    return get_hotp(base32_encoded_secret, counter, ctx->digits, ctx->algo, err);
}

char* cotp_ctx_steam_totp(cotp_ctx* ctx, const char* base32_encoded_secret, cotp_error_t* err)
{
    if (!ctx) {
        if (err) *err = INVALID_USER_INPUT;
        return NULL;
    }
    return get_steam_totp(base32_encoded_secret, ctx->period, err);
}

char* cotp_ctx_steam_totp_at(cotp_ctx* ctx, const char* base32_encoded_secret, long timestamp, cotp_error_t* err)
{
    if (!ctx) {
        if (err) *err = INVALID_USER_INPUT;
        return NULL;
    }
    return get_steam_totp_at(base32_encoded_secret, timestamp, ctx->period, err);
}

#ifdef COTP_ENABLE_VALIDATION
int cotp_ctx_validate_totp(cotp_ctx* ctx,
                           const char*   user_code,
                           const char*   base32_encoded_secret,
                           long          timestamp,
                           int           window,
                           int*          matched_delta,
                           cotp_error_t* err)
{
    if (!ctx) {
        if (err) *err = INVALID_USER_INPUT;
        if (matched_delta) *matched_delta = 0;
        return 0;
    }
    return validate_totp_in_window(user_code, base32_encoded_secret, timestamp,
                                   ctx->digits, ctx->period, ctx->algo,
                                   window, matched_delta, err);
}
#endif
