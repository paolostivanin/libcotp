# libcotp
<a href="https://scan.coverity.com/projects/paolostivanin-libcotp">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/12748/badge.svg"/>
</a>

C library that generates TOTP and HOTP according to [RFC-6238](https://www.rfc-editor.org/rfc/rfc6238).

## Requirements

- GCC or Clang and CMake
- One crypto backend:
  - libgcrypt ≥ 1.8.0
  - OpenSSL ≥ 3.0.0
  - MbedTLS 2.x or 3.x

## Build and Install

```sh
git clone https://github.com/paolostivanin/libcotp.git
cd libcotp
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make
sudo make install
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `-DBUILD_TESTS=ON` | OFF | Build tests |
| `-DBUILD_SHARED_LIBS=OFF` | ON | Build static instead of shared |
| `-DHMAC_WRAPPER=<gcrypt|openssl|mbedtls>` | gcrypt | Select crypto backend |
| `-DCOTP_ENABLE_VALIDATION=ON` | OFF | Enable validation helper APIs |

---

## Public API

```c
char *get_totp(const char *base32_secret,
               int digits,
               int period,
               int algo,
               cotp_error_t *err);

char *get_steam_totp(const char *base32_secret,
                     int period,
                     cotp_error_t *err);

char *get_hotp(const char *base32_secret,
               long counter,
               int digits,
               int algo,
               cotp_error_t *err);

char *get_totp_at(const char *base32_secret,
                  long timestamp,
                  int digits,
                  int period,
                  int algo,
                  cotp_error_t *err);

int64_t otp_to_int(const char *otp,
                   cotp_error_t *err);
```

### Parameter Constraints

- `base32_secret`: Base32 encoded (may contain spaces). `NULL` is invalid.
- `digits`: 4–10 inclusive
- `period`: 1–120 seconds inclusive
- `algo`: `SHA1`, `SHA256`, `SHA512`
- `counter`: non-negative
- `timestamp`: UNIX epoch seconds

Secrets are normalized (spaces removed, lowercase → uppercase).

---

## Ownership and Lifetime

- On success, OTP functions return `char *`. Caller must `free()`.
- On error, they return `NULL` and set `err` if non-NULL.
- If `err == NULL`, functions still behave correctly using an internal error variable.
- `otp_to_int()` never allocates:
  - returns `-1` on invalid input
  - returns integer on success
  - strips leading zeroes and sets `MISSING_LEADING_ZERO` when applicable

Example:

```c
cotp_error_t err;
char *code = get_totp("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", 6, 30, COTP_SHA1, &err);
if (!code) {
    // handle error
}
free(code);
```

---

## Error Model

| Error | Meaning |
|-------|---------|
| `NO_ERROR` | Success |
| `VALID` | Validation helper matched |
| `WHMAC_ERROR` | Backend crypto error |
| `INVALID_B32_INPUT` | Secret not valid Base32 |
| `INVALID_ALGO` | Unsupported algorithm |
| `INVALID_PERIOD` | Period not in allowed range |
| `INVALID_DIGITS` | Digits not in allowed range |
| `INVALID_COUNTER` | `counter < 0` |
| `INVALID_USER_INPUT` | NULL or malformed user input |
| `MISSING_LEADING_ZERO` | Leading zeroes stripped |
| `MEMORY_ALLOCATION_ERROR` | Allocation failure |
| `EMPTY_STRING` | Input was empty |

Return rules:

- `get_totp`, `get_totp_at`, `get_steam_totp`, `get_hotp` → `NULL` on failure
- `otp_to_int` → `-1` on failure

---

## Validation Helpers (optional)

Enabled with `-DCOTP_ENABLE_VALIDATION=ON`:

```c
int validate_totp_in_window(const char *user_code,
                            const char *base32_secret,
                            long timestamp,
                            int digits,
                            int period,
                            int sha_algo,
                            int window,
                            int *matched_delta,
                            cotp_error_t *err);
```

Returns:

- `1` on match within `[-window, +window]` periods (sets `VALID`)
- `0` otherwise

---

## Context API

```c
cotp_ctx *cotp_ctx_create(int digits, int period, int sha_algo);
char     *cotp_ctx_totp_at(cotp_ctx *ctx, const char *base32_secret, long timestamp, cotp_error_t *err);
char     *cotp_ctx_totp(cotp_ctx *ctx, const char *base32_secret, cotp_error_t *err);
void      cotp_ctx_free(cotp_ctx *ctx);
```

---

## Base32 Encoding / Decoding

```c
char *base32_encode(const unsigned char *data,
                    size_t len,
                    cotp_error_t *err);

unsigned char *base32_decode(const char *user_data,
                             size_t data_len,
                             cotp_error_t *err);

bool is_string_valid_b32(const char *user_data);
```

Behavior:

- `NULL` on error (sets `err`)
- empty input → empty output + `EMPTY_STRING`
- spaces allowed
- invalid base32 → `INVALID_B32_INPUT`

---

## Operational Notes

- TOTP requires correct system time (use NTP)
- Validation should allow small window (±1–2 periods)
- Secrets should be handled securely
