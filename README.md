# libcotp
<a href="https://scan.coverity.com/projects/paolostivanin-libcotp">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/12748/badge.svg"/>
</a>

C library that generates TOTP and HOTP according to [RFC-6238](https://tools.ietf.org/html/rfc6238)

## Requirements
- [libbaseencode](https://github.com/paolostivanin/libbaseencode)
- GCC/Clang and CMake to build the library
- libgcrypt

## Build and Install
```
$ git clone https://github.com/paolostivanin/libcotp.git
$ cd libcotp
$ mkdir build && cd $_
$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ../   # add -DBUILD_TESTING=ON if you want to compile also the tests
$ make
# make install
```

## How To Use It
```
char *totp = get_totp (const char *base32_encoded_secret, int digits, int period, int algo, cotp_error_t *err);
free (totp);

char *steam_totp = get_steam_totp (const char *secret, int period, cotp_error_t *err)

char *hotp = get_hotp (const char *base32_encoded_secret, long counter, int digits, int algo, cotp_error_t *err);
free (hotp);

char *get_totp_at (const char *base32_encoded_secret, long target_date, int digits, int algo, cotp_error_t *err)

int is_valid = totp_verify (const har *base32_encoded_secret, const char *totp, int digits, int period, int algo, cotp_error_t *err);

int is_valid = hotp_verify (const char *base32_encoded_secret, long counter, digits, char *hotp, int algo, cotp_error_t *err);
```

where:
- `secret_key` is the **base32 encoded** secret. Usually, a website gives you the secret already base32 encoded, so you should pay attention to not encode the secret again.
The format of the secret can either be `hxdm vjec jjws` or `HXDMVJECJJWS`. In the first case, the library will normalize the secret to second format before computing the OTP.
- `digits` is between `3` and `10` inclusive
- `period` is between `1` and `120` inclusive
- `counter` is a value decided with the server
- `target_date` is the target date specified as the unix epoch format in seconds
- `algo` is either `SHA1`, `SHA256` or `SHA512`

## Errors
`get_totp`, `get_hotp` and `get_totp_at` return `NULL` if an error occurs and `err` is set accordingly. The following errors are currently supported:
- `GCRYPT_VERSION_MISMATCH`, set if the installed Gcrypt library is too old
- `INVALID_B32_INPUT`, set if the given input is not valid base32 text
- `INVALID_ALGO`, set if the given algo is not supported by the library
- `INVALID_PERIOD`, set if `period` is `<= 0` or `> 120` seconds
- `INVALID_DIGITS`, set if `digits` is `< 3` or `> 10`

`totp_verify` and `hotp_verify` can return, in addition to one of the previous code, also the error `INVALID_OTP` if the given OTP doesn't match the computed one.

In case of success, the value returned by `get_totp`, `get_hotp` and `get_totp_at` **must be freed** once no longer needed.

