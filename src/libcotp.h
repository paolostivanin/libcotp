#pragma once

#define TOTP_NOT_VALID 0
#define TOTP_VALID 1
#define HOTP_NOT_VALID TOTP_NOT_VALID
#define HOTP_VALID TOTP_VALID

char *get_hotp (const char *secret_key, long counter, int digits);
char *get_totp (const char *secret_key, int digits);
int totp_verify (const char *secret_key, int digits, char *user_totp);
int hotp_verify (const char *secret_key, long counter, int digits, const char *user_hotp);