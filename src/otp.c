#include <stdio.h>
#include <time.h>
#include <string.h>
#include <gcrypt.h>
#include <baseencode.h>
#include "cotp.h"


#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64

static int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};


static int
check_gcrypt()
{
    if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        if (!gcry_check_version("1.5.0")) {
            fprintf(stderr, "libgcrypt v1.5.0 and above is required\n");
            return -1;
        }
        gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    }
    return 0;
}


static char *
normalize_secret (const char *K)
{
    char *nK = calloc (1, strlen (K) + 1);

    int i = 0, j = 0;
    while (K[i] != '\0') {
        if (K[i] != ' ') {
            if (K[i] >= 'a' && K[i] <= 'z') {
                nK[j++] = (char) (K[i] - 32);
            } else {
                nK[j++] = K[i];
            }
        }
        i++;
    }
    return nK;
}


static int
truncate(unsigned const char *hmac, int N, int algo)
{
    // take the lower four bits of the last byte
    int offset = 0;
    switch (algo) {
        case SHA1:
            offset = (hmac[SHA1_DIGEST_SIZE-1] & 0x0f);
            break;
        case SHA256:
            offset = (hmac[SHA256_DIGEST_SIZE-1] & 0x0f);
            break;
        case SHA512:
            offset = (hmac[SHA512_DIGEST_SIZE-1] & 0x0f);
            break;
        default:
            break;
    }

    // Starting from the offset, take the successive 4 bytes while stripping the topmost bit to prevent it being handled as a signed integer
    int bin_code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | ((hmac[offset + 3] & 0xff));

    int token = bin_code % DIGITS_POWER[N];

    return token;
}


static unsigned char *
compute_hmac(const char *K, long C, int algo)
{
    size_t secret_len = (size_t) ((strlen(K) + 1.6 - 1) / 1.6);

    char *normalized_K = normalize_secret (K);
    unsigned char *secret = base32_decode(normalized_K, strlen(normalized_K));
    free (normalized_K);
    if (secret == NULL) {
        return NULL;
    }

    unsigned char C_reverse_byte_order[8];
    int j, i;
    for (j = 0, i = 7; j < 8 && i >= 0; j++, i--)
        C_reverse_byte_order[i] = ((unsigned char *) &C)[j];

    gcry_md_hd_t hd;
    gcry_md_open(&hd, algo, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey(hd, secret, secret_len);
    gcry_md_write(hd, C_reverse_byte_order, sizeof(C_reverse_byte_order));
    gcry_md_final (hd);
    unsigned char *hmac = gcry_md_read(hd, algo);

    free(secret);

    return hmac;
}


static char *
finalize(int N, int tk)
{
    char *token = malloc((size_t) N + 1);
    if (token == NULL) {
        printf("[E] Error during memory allocation\n");
        return NULL;
    } else {
        if (N == 6)
            snprintf(token, 7, "%.6d", tk);
        else
            snprintf(token, 9, "%.8d", tk);
    }
    return token;
}


static int
check_otp_len(int N)
{
    if ((N != 6) && (N != 8)) {
        fprintf(stderr, "Only 6 or 8 is allowed as number of digits. Falling back to 6.\n");
        return 6;
    } else {
        return N;
    }
}


static int
check_algo(int algo)
{
    if (algo != SHA1 && algo != SHA256 && algo != SHA512) {
        return INVALID_ALGO;
    } else {
        return VALID;
    }
}


char *
get_hotp(const char *K, long C, int N, int algo, cotp_error_t *err_code)
{
    if (check_gcrypt() == -1) {
        *err_code = GCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    if (check_algo(algo) == INVALID_ALGO) {
        *err_code = INVALID_ALGO;
        return NULL;
    }

    N = check_otp_len(N);

    unsigned char *hmac = compute_hmac(K, C, algo);
    if (hmac == NULL) {
        *err_code = INVALID_B32_INPUT;
        return NULL;
    }
    int tk = truncate(hmac, N, algo);
    char *token = finalize(N, tk);
    return token;
}


char *
get_totp(const char *K, int N, int algo, cotp_error_t *err_code)
{
    if (check_gcrypt() == -1) {
        *err_code = GCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    N = check_otp_len(N);

    long TC = ((long) time(NULL)) / 30;
    cotp_error_t err;
    char *token = get_hotp(K, TC, N, algo, &err);
    if (token == NULL) {
        *err_code = err;
        return NULL;
    }
    return token;
}


char *
get_totp_at(const char *K, long T, int N, int algo, cotp_error_t *err_code)
{
    if (check_gcrypt() == -1) {
        *err_code = GCRYPT_VERSION_MISMATCH;
        return NULL;
    }

    N = check_otp_len(N);

    long TC = T / 30;
    cotp_error_t err;

    char *token = get_hotp(K, TC, N, algo, &err);
    if (token == NULL) {
        *err_code = err;
        return NULL;
    }
    return token;
}


int
totp_verify(const char *K, int N, const char *user_totp, int algo)
{
    cotp_error_t err;
    char *current_totp = get_totp(K, N, algo, &err);
    if (current_totp == NULL) {
        return err;
    }
    int token_status;
    if (strcmp(current_totp, user_totp) != 0) {
        token_status = INVALID_OTP;
    } else {
        token_status = VALID;
    }
    free(current_totp);
    return token_status;
}


int
hotp_verify(const char *K, long C, int N, const char *user_hotp, int algo)
{
    cotp_error_t err;
    char *current_hotp = get_hotp(K, C, N, algo, &err);
    if (current_hotp == NULL) {
        return err;
    }
    int token_status;
    if (strcmp(current_hotp, user_hotp) != 0) {
        token_status = INVALID_OTP;
    } else {
        token_status = VALID;
    }
    free(current_hotp);
    return token_status;
}

// TODO fix doc
// TODO add string like strerror(errno)