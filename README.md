# libcotp
<a href="https://scan.coverity.com/projects/paolostivanin-libcotp">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/12748/badge.svg"/>
</a>

C library that generates TOTP and HOTP according to [RFC-6238](https://tools.ietf.org/html/rfc6238)

## Requirements
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

char *steam_totp = get_steam_totp (const char *secret, int period, cotp_error_t *err);
free (steam_totp);

char *hotp = get_hotp (const char *base32_encoded_secret, long counter, int digits, int algo, cotp_error_t *err);
free (hotp);

char *totp_at = get_totp_at (const char *base32_encoded_secret, long target_date, int digits, int algo, cotp_error_t *err);
free (totp_at);

int64_t otp_to_int (const char *otp, cotp_error_t *err_code);
```

where:
- `secret_key` is the **base32 encoded** secret. Usually, a website gives you the secret already base32 encoded, so you should pay attention to not encode the secret again.
The format of the secret can either be `hxdm vjec jjws` or `HXDMVJECJJWS`. In the first case, the library will normalize the secret to second format before computing the OTP.
- `digits` is between `3` and `10` inclusive
- `period` is between `1` and `120` inclusive
- `counter` is a value decided with the server
- `target_date` is the target date specified as the unix epoch format in seconds
- `algo` is either `SHA1`, `SHA256` or `SHA512`

## Return values
`get_totp`, `get_hotp` and `get_totp_at` return `NULL` if an error occurs and `err` is set to one of the following values:

Errors:
- `GCRYPT_VERSION_MISMATCH`, set if the installed Gcrypt library is too old
- `INVALID_B32_INPUT`, set if the given input is not valid base32 text
- `INVALID_ALGO`, set if the given algo is not supported by the library
- `INVALID_PERIOD`, set if `period` is `<= 0` or `> 120` seconds
- `INVALID_DIGITS`, set if `digits` is `< 4` or `> 10`
- `MEMORY_ALLOCATION_ERROR`, set if an error happened during memory allocation
- `INVALID_USER_INPUT`, set if the given input is not valid
- `INVALID_COUNTER`, set if `counter` is `< 0`

All good:
- `NO_ERROR`, set if no error occurred
- `VALID`, set if the given OTP is valid

The function `otp_to_int`:
* returns `-1` if an error occurs and sets `err` to `INVALID_USER_INPUT`.
* warns the user if the leading zero is missing. For example, since the otp string `"012345"` **can't** be returned as the integer `012345` (because it would be interpreted as octal number), the function returns `12345` and sets `err` to `MISSING_LEADING_ZERO`)

In case of success, the value returned by `get_totp`, `get_hotp`, `get_totp_at` and `get_steam_totp` **must be freed** once no longer needed.

# Base32 encoding and decoding
Since release 2.0.0, libbaseencode has been merged with libcotp. This means that you can now use base32 functions by just including `cotp.h`:

```
char    *base32_encode     (const uchar  *user_data,
                            size_t        data_len,
                            cotp_error_t *err_code);

uchar   *base32_decode     (const char   *user_data,
                            size_t        data_len,
                            cotp_error_t *err_code);
```

where:
- `user_data` is the data to be encoded/decoded
- `data_len` is the length of the data to be encoded/decoded
- `err_code` is where the error is stored

`base32_encode` returns `NULL` if an error occurs and `err_code` is set to one of the following values:
  - `INVALID_USER_INPUT`, set if the given input is not valid
  - `MEMORY_ALLOCATION_ERROR`, set if an error happened during memory allocation
  - `INVALID_USER_INPUT`, set if the given input is not valid

`base32_decode` returns `NULL` if an error occurs and `err_code` is set to one of the following values:
- `INVALID_USER_INPUT`, set if the given input is not valid
- `MEMORY_ALLOCATION_ERROR`, set if an error happened during memory allocation
- `INVALID_B32_INPUT`, set if the given input is not valid base32 text
- `INVALID_USER_INPUT`, set if the given input is not valid

Both functions return and empty string if the input is an empty string. In such a case, `err` is set to `EMPTY_STRING`.