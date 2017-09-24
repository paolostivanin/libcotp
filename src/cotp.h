#pragma once
#include <gcrypt.h>

#define INVALID_ALGO -4
#define HOTP_NOT_VALID -3
#define TOTP_NOT_VALID -2
#define GCRYPT_VERSION_MISMATCH -1
#define TOTP_VALID 1
#define HOTP_VALID 2
#define VALID_ALGO 3

#define SHA1 GCRY_MD_SHA1
#define SHA256 GCRY_MD_SHA256
#define SHA512 GCRY_MD_SHA512

char *get_hotp (const char *base32_encoded_secret, long counter, int digits, int sha_algo);
char *get_totp (const char *base32_encoded_secret, int digits, int sha_algo);
char *get_totp_at (const char *base32_encoded_secret, long time, int digits, int sha_algo);
int totp_verify (const char *base32_encoded_secret, int digits, const char *user_totp, int sha_algo);
int hotp_verify (const char *base32_encoded_secret, long counter, int digits, const char *user_hotp, int sha_algo);