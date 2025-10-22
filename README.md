# libcotp
<a href="https://scan.coverity.com/projects/paolostivanin-libcotp">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/12748/badge.svg"/>
</a>

C library that generates TOTP and HOTP according to [RFC-6238](https://tools.ietf.org/html/rfc6238)

## Requirements
- GCC/Clang and CMake to build the library
- libgcrypt >= 1.8.0 or openssl >= 3.0.0 or mbedtls (works with both 2.x and 3.x)

## Build and Install
```
$ git clone https://github.com/paolostivanin/libcotp.git
$ cd libcotp
$ mkdir build && cd $_
$ cmake -DCMAKE_INSTALL_PREFIX=/usr ..
$ make
$ sudo make install
```

Available options you can pass to `cmake`:
* `-DBUILD_TESTS=ON`: if you want to compile also the tests (default **OFF**)
* `-DBUILD_SHARED_LIBS=OFF`: if you want to build libcotp as a static library (default **ON**)
* `-DHMAC_WRAPPER="<gcrypt|openssl|mbedtls>"`: you can choose between GCrypt, OpenSSL or MbedTLS (default **gcrypt**)
* `-DCOTP_ENABLE_VALIDATION=ON`: enable optional helper APIs for validating TOTP codes within a time window (off by default)

## How To Use It
```
char *totp        = get_totp       (const char   *base32_encoded_secret,
                                    int           digits,
                                    int           period,
                                    int           algo,
                                    cotp_error_t *err);

char *steam_totp  = get_steam_totp (const char   *secret,
                                    int           period,
                                    cotp_error_t *err);

char *hotp        = get_hotp       (const char   *base32_encoded_secret,
                                    long          counter,
                                    int           digits,
                                    int           algo,
                                    cotp_error_t *err);

char *totp_at     = get_totp_at    (const char   *base32_encoded_secret,
                                    long          target_date,
                                    int           digits,
                                    int           period,
                                    int           algo,
                                    cotp_error_t *err);

int64_t otp_i     = otp_to_int     (const char   *otp,
                                    cotp_error_t *err_code);
```

where:
- `base32_encoded_secret` is the **base32 encoded** secret. Usually, a website gives you the secret already base32 encoded, so you should pay attention to not encode the secret again. The format of the secret can either be `hxdm vjec jjws` or `HXDMVJECJJWS`. In the first case, the library will normalize the secret to second format before computing the OTP.
- `digits` is between `4` and `10` inclusive
- `period` is between `1` and `120` inclusive
- `counter` is a value decided with the server
- `target_date` is the target date specified as the **unix epoch format in seconds**
- `algo` is either `SHA1`, `SHA256` or `SHA512`

### Ownership and lifetime
- All OTP/base32 API functions that return char* or uchar* allocate a new buffer on success. You own it; call free() when done.
- On error, these functions return NULL and set the provided cotp_error_t out-parameter.
- otp_to_int never allocates. It returns -1 on invalid input (err = INVALID_USER_INPUT). If the input had leading zeroes, it returns the integer value without them and sets err = MISSING_LEADING_ZERO.

Example:
```
cotp_error_t err;
char *code = get_totp("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", 6, 30, SHA1, &err);
if (!code) {
    // handle error
}
// use code
free(code);
```

### Security notes (operational)
- Time source: TOTP correctness depends on accurate time. Sync your clock (e.g., NTP). Consider using a monotonic source for step math when appropriate.
- Drift and validation: When validating user-entered TOTPs, allow a small window (±1 or ±2 periods) and rate-limit attempts.
- Secret handling: Treat decoded secrets as sensitive; wipe memory when feasible and store secrets securely.

### Optional helpers
- Validation (behind `-DCOTP_ENABLE_VALIDATION=ON`):
  - `int validate_totp_in_window(const char* user_code, const char* base32_secret, long timestamp, int digits, int period, int sha_algo, int window, int* matched_delta, cotp_error_t* err)`
  - Returns 1 on match within [-window, +window] steps, 0 otherwise. On match sets `err = VALID` and `matched_delta` to the offset.
- Context API (convenience wrapper for repeated computations with same parameters):
  - `cotp_ctx* cotp_ctx_create(int digits, int period, int sha_algo);`
  - `char* cotp_ctx_totp_at(cotp_ctx* ctx, const char* base32_secret, long timestamp, cotp_error_t* err);`
  - `char* cotp_ctx_totp(cotp_ctx* ctx, const char* base32_secret, cotp_error_t* err);`
  - `void cotp_ctx_free(cotp_ctx* ctx);`

## Return values
`get_totp`, `get_hotp` and `get_totp_at` return `NULL` if an error occurs and `err` is set to one of the following values:

Errors:
- `WHMAC_ERROR`, generic error from the selected HMAC backend (initialization/finalization failure)
- `INVALID_B32_INPUT`, set if the given input is not valid base32 text
- `INVALID_ALGO`, set if the given algo is not supported by the library
- `INVALID_PERIOD`, set if `period` is `<= 0` or `> 120` seconds
- `INVALID_DIGITS`, set if `digits` is `< 4` or `> 10`
- `MEMORY_ALLOCATION_ERROR`, set if an error happened during memory allocation
- `INVALID_USER_INPUT`, set if the given input is not valid
- `INVALID_COUNTER`, set if `counter` is `< 0`

All good:
- `NO_ERROR`, set if no error occurred
- `VALID`, used by optional validation helper APIs (when enabled) to indicate that a provided OTP matched within the allowed window

The function `otp_to_int`:
* returns `-1` if an error occurs and sets `err` to `INVALID_USER_INPUT`.
* warns the user if the leading zero is missing. For example, since the otp string `"012345"` **can't** be returned as the integer `012345` (because it would be interpreted as octal number), the function returns `12345` and sets `err` to `MISSING_LEADING_ZERO`)

In case of success, the value returned by `get_totp`, `get_hotp`, `get_totp_at` and `get_steam_totp` **must be freed** once no longer needed.

# Base32 encoding and decoding
Since release 2.0.0, libbaseencode has been merged with libcotp. This means that you can now use base32 functions by just including `cotp.h`:

```
char  *base32_encode (const uchar  *user_data,
                      size_t        data_len,
                      cotp_error_t *err_code);

uchar *base32_decode (const char   *user_data,
                      size_t        data_len,
                      cotp_error_t *err_code);

bool   is_string_valid_b32 (const char *user_data);
```

where:
- `user_data` is the data to be encoded or decoded
- `data_len` is the length of the data to be encoded/decoded
- `err_code` is where the error is stored

`base32_encode` returns `NULL` if an error occurs and `err_code` is set to one of the following values:
- `INVALID_USER_INPUT`, set if the given input is not valid
- `MEMORY_ALLOCATION_ERROR`, set if an error happened during memory allocation

`base32_decode` returns `NULL` if an error occurs and `err_code` is set to one of the following values:
- `INVALID_USER_INPUT`, set if the given input is not valid
- `MEMORY_ALLOCATION_ERROR`, set if an error happened during memory allocation
- `INVALID_B32_INPUT`, set if the given input is not valid base32 text
- `INVALID_USER_INPUT`, set if the given input is not valid

Both functions return an empty string if the input is an empty string. In such a case, `err` is set to `EMPTY_STRING`.

`is_string_valid_b32` returns `true` if `user_data` is a valid base32 encoded string, `false` otherwise. Please note that `user_data` can contain spaces, since
the function will also take care of trimming those.
